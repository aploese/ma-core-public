/*
    Copyright (C) 2014 Infinite Automation Systems Inc. All rights reserved.
    @author Matthew Lohbihler
 */
package com.serotonin.m2m2.db;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.MissingResourceException;

import javax.sql.DataSource;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.datasource.DataSourceUtils;

import com.serotonin.ShouldNeverHappenException;
import com.serotonin.db.DaoUtils;
import com.serotonin.db.spring.ConnectionCallbackVoid;
import com.serotonin.db.spring.ExtendedJdbcTemplate;
import com.serotonin.m2m2.Common;
import com.serotonin.m2m2.ILifecycle;
import com.serotonin.m2m2.db.dao.PointValueDao;
import com.serotonin.m2m2.db.dao.PointValueDaoMetrics;
import com.serotonin.m2m2.db.dao.PointValueDaoSQL;
import com.serotonin.m2m2.db.dao.SystemSettingsDao;
import com.serotonin.m2m2.db.dao.UserDao;
import com.serotonin.m2m2.db.upgrade.DBUpgrade;
import com.serotonin.m2m2.module.DatabaseSchemaDefinition;
import com.serotonin.m2m2.module.ModuleRegistry;
import com.serotonin.m2m2.module.PermissionDefinition;
import com.serotonin.m2m2.module.definitions.permissions.SuperadminPermissionDefinition;
import com.serotonin.m2m2.vo.User;
import com.serotonin.m2m2.vo.template.DefaultDataPointPropertiesTemplateFactory;
import com.serotonin.provider.Providers;

abstract public class DatabaseProxy {
    public enum DatabaseType {
        DERBY {
            @Override
            DatabaseProxy getImpl() {
                return new DerbyProxy();
            }
        },
        H2 {
            @Override
            DatabaseProxy getImpl() {
                return new H2Proxy();
            }
        },
        MSSQL {
            @Override
            DatabaseProxy getImpl() {
                return new MSSQLProxy();
            }
        },
        MYSQL {
            @Override
            DatabaseProxy getImpl() {
                return new MySQLProxy();
            }
        },
        POSTGRES {
            @Override
            DatabaseProxy getImpl() {
                return new PostgresProxy();
            }
        };

        abstract DatabaseProxy getImpl();
    }

    public static DatabaseProxy createDatabaseProxy() {
        String type = Common.envProps.getString("db.type", "h2");
        DatabaseType dt = DatabaseType.valueOf(type.toUpperCase());

        if (dt == null)
            throw new IllegalArgumentException("Unknown database type: " + type);

        return dt.getImpl();
    }

    private final Log log = LogFactory.getLog(DatabaseProxy.class);
    private NoSQLProxy noSQLProxy;
    private Boolean useMetrics;

    public void initialize(ClassLoader classLoader) {
        initializeImpl("");

        useMetrics = Common.envProps.getBoolean("db.useMetrics", false);

        ExtendedJdbcTemplate ejt = new ExtendedJdbcTemplate();
        ejt.setDataSource(getDataSource());

        try {
            if (newDatabaseCheck(ejt)) {
                // Check if we should convert from another database.
                String convertTypeStr = null;
                try {
                    convertTypeStr = Common.envProps.getString("convert.db.type");
                }
                catch (MissingResourceException e) {
                    convertTypeStr = "";
                }

                if (!StringUtils.isBlank(convertTypeStr)) {
                    // Found a database type from which to convert.
                    DatabaseType convertType = DatabaseType.valueOf(convertTypeStr.toUpperCase());
                    if (convertType == null)
                        throw new IllegalArgumentException("Unknown convert database type: " + convertType);

                    // TODO check that the convert source has the current DB version, or upgrade it if not.

                    DatabaseProxy sourceProxy = convertType.getImpl();
                    sourceProxy.initializeImpl("convert.");

                    DBConvert convert = new DBConvert();
                    convert.setSource(sourceProxy);
                    convert.setTarget(this);
                    try {
                        convert.execute();
                    }
                    catch (SQLException e) {
                        throw new ShouldNeverHappenException(e);
                    }

                    sourceProxy.terminate();
                }
                else {
                     SystemSettingsDao systemSettingsDao = new SystemSettingsDao();

                    // Record the current version.
                    systemSettingsDao.setValue(SystemSettingsDao.DATABASE_SCHEMA_VERSION,
                            Integer.toString(Common.getDatabaseSchemaVersion()));

                    // Add the settings flag that this is a new instance. This flag is removed when an administrator
                    // logs in.
                    systemSettingsDao.setBooleanValue(SystemSettingsDao.NEW_INSTANCE, true);
                    
                    /**
                     * Add a startup task to run after the Audit system is ready 
                     */
                    Providers.get(ILifecycle.class).addStartupTask(new Runnable() {
                        @Override
                        public void run() {
                        	// New database. Create a default user.
                            User user = new User();
                            user.setId(Common.NEW_ID);
                            user.setUsername("admin");
                            user.setPassword(Common.encrypt("admin"));
                            user.setEmail("admin@yourMangoDomain.com");
                            user.setPhone("");
                            user.setPermissions(SuperadminPermissionDefinition.GROUP_NAME);
                            user.setDisabled(false);
                            UserDao.instance.saveUser(user);
                        	
                            DefaultDataPointPropertiesTemplateFactory factory = new DefaultDataPointPropertiesTemplateFactory();
                            factory.saveDefaultTemplates();
                            
                            //Add the Default Permissions for the UI
                            List<PermissionDefinition> defs = ModuleRegistry.getDefinitions(PermissionDefinition.class);
                            for(PermissionDefinition def : defs)
                            	def.install();
                       }
                    });
                }
            }
            else
                // The database exists, so let's make its schema version matches the application version.
                DBUpgrade.checkUpgrade();

            // Check if we are using NoSQL
            if (NoSQLProxyFactory.instance.getProxy() != null) {
                noSQLProxy = NoSQLProxyFactory.instance.getProxy();
                noSQLProxy.initialize();
            }

        }
        catch (CannotGetJdbcConnectionException e) {
            log.fatal("Unable to connect to database of type " + getType().name(), e);
            throw e;
        }

        // Allow modules to upgrade themselves
        for (DatabaseSchemaDefinition def : ModuleRegistry.getDefinitions(DatabaseSchemaDefinition.class))
            DBUpgrade.checkUpgrade(def, classLoader);

        postInitialize(ejt);
    }

	private boolean newDatabaseCheck(ExtendedJdbcTemplate ejt) {
        boolean coreIsNew = false;

        if (!tableExists(ejt, "users")) {
            // The users table wasn't found, so assume that this is a new instance.
            // Create the tables
            try {
                runScriptFile(Common.MA_HOME + "/db/createTables-" + getType().name() + ".sql", new FileOutputStream(
                        new File(Common.getLogsDir(), "createTables.log")));
            }
            catch (FileNotFoundException e) {
                throw new ShouldNeverHappenException(e);
            }
            coreIsNew = true;
        }

        for (DatabaseSchemaDefinition def : ModuleRegistry.getDefinitions(DatabaseSchemaDefinition.class))
            def.newInstallationCheck(ejt);

        return coreIsNew;
    }

    abstract public DatabaseType getType();

    public void terminate() {
        terminateImpl();
        // Check if we are using NoSQL
        if (NoSQLProxyFactory.instance.getProxy() != null) {
            noSQLProxy = NoSQLProxyFactory.instance.getProxy();
            noSQLProxy.shutdown();
        }
    }

    abstract public void terminateImpl();

    abstract public DataSource getDataSource();

    abstract public double applyBounds(double value);

    abstract public File getDataDirectory();

    /**
     * 
     * @return size of Database in bytes or null if don't know
     */
    abstract public Long getDatabaseSizeInBytes();

    abstract public void executeCompress(ExtendedJdbcTemplate ejt);

    abstract protected void initializeImpl(String propertyPrefix);

    abstract public boolean tableExists(ExtendedJdbcTemplate ejt, String tableName);

    abstract public int getActiveConnections();

    abstract public int getIdleConnections();

    protected void postInitialize(ExtendedJdbcTemplate ejt) {
        // no op - override as necessary
    }

    abstract public void runScript(String[] script, final OutputStream out) throws Exception;

    abstract public void runScript(InputStream in, final OutputStream out);

    abstract public String getTableListQuery();

    public void runScriptFile(String scriptFile, OutputStream out) {
        try {
            runScript(new FileInputStream(scriptFile), out);
        }
        catch (FileNotFoundException e) {
            throw new ShouldNeverHappenException(e);
        }
    }

    public void doInConnection(ConnectionCallbackVoid callback) {
        DataSource dataSource = getDataSource();
        Connection conn = null;
        try {
            conn = DataSourceUtils.getConnection(dataSource);
            conn.setAutoCommit(false);
            callback.doInConnection(conn);
            conn.commit();
        }
        catch (Exception e) {
            try {
                if (conn != null)
                    conn.rollback();
            }
            catch (SQLException e1) {
                log.warn("Exception during rollback", e1);
            }

            // Wrap and rethrow
            throw new ShouldNeverHappenException(e);
        }
        finally {
            if (conn != null)
                DataSourceUtils.releaseConnection(conn, dataSource);
        }
    }

    abstract public <T> List<T> doLimitQuery(DaoUtils dao, String sql, Object[] args, RowMapper<T> rowMapper, int limit);

    public long doLimitDelete(ExtendedJdbcTemplate ejt, String sql, Object[] args, int chunkSize, int chunkWait,
            int limit) {
        sql = getLimitDelete(sql, chunkSize);

        long total = 0;
        while (true) {
            int cnt;
            if (args == null)
                cnt = ejt.update(sql);
            else
                cnt = ejt.update(sql, args);

            total += cnt;

            if (cnt < chunkSize || (limit > 0 && total >= limit))
                break;

            if (chunkWait > 0) {
                try {
                    Thread.sleep(chunkWait);
                }
                catch (InterruptedException e) {
                    // no op
                }
            }
        }

        return total;
    }

    abstract protected String getLimitDelete(String sql, int chunkSize);

    public String getDatabasePassword(String propertyPrefix) {
        String input = Common.envProps.getString(propertyPrefix + "db.password");
        return new DatabaseAccessUtils().decrypt(input);
    }

    public void setNoSQLProxy(NoSQLProxy proxy) {
        this.noSQLProxy = proxy;
    }

    public PointValueDao newPointValueDao() {
        if (noSQLProxy == null) {
            if (useMetrics)
                return new PointValueDaoMetrics(new PointValueDaoSQL());
            return new PointValueDaoSQL();
        }

        if (useMetrics)
            return noSQLProxy.createPointValueDaoMetrics();
        return noSQLProxy.createPointValueDao();
    }

    /**
     * Allow access to the NoSQL Proxy
     * 
     * @return
     */
    public NoSQLProxy getNoSQLProxy() {
        return noSQLProxy;
    }

    //  TODO: could potentially expose Logging DAO for use in application	
    //  	currently not implemented except for TinyTSDB
    //	/**
    //	 * Get an instance of the Logging Dao
    //	 * 
    //	 * @return
    //	 */
    //	public LoggingDao newLoggingDao() {
    //        if (noSQLProxy == null){
    //        	if(useMetrics)
    //        		return new LoggingDaoMetrics(new LoggingDaoSQL());
    //        	else
    //        		return new LoggingDaoSQL();
    //        }else{
    //        	if(useMetrics)
    //        		return new LoggingDaoMetrics(noSQLProxy.createLoggingDao());
    //        	else
    //        		return noSQLProxy.createLoggingDao();
    //        }
    //	}
    
}
