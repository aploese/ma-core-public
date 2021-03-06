/**
 * Copyright (C) 2015 Infinite Automation Software. All rights reserved.
 * @author Terry Packer
 */
package com.infiniteautomation.mango.db.query.pojo;

import java.lang.reflect.InvocationTargetException;
import java.util.Comparator;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.infiniteautomation.mango.db.query.SortOption;

/**
 * @author Terry Packer
 *
 */
public class SortOptionComparator<T> implements Comparator<T>{
	private static Log LOG = LogFactory.getLog(SortOptionComparator.class);
			
	private SortOption sort;
	
	public SortOptionComparator(SortOption sort){
		this.sort = sort;
	}
	
	/* (non-Javadoc)
	 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public int compare(T o1, T o2) {
		try {
			Object v1 = PropertyUtils.getProperty(o1, sort.getAttribute());
			Comparable<Comparable<?>> c1;
			if(v1 instanceof Comparable)
				c1 = (Comparable<Comparable<?>>)v1;
			else
				return 0;
			Object v2 = PropertyUtils.getProperty(o2, sort.getAttribute());
			Comparable<Comparable<?>> c2;
			if(v2 instanceof Comparable)
				c2 = (Comparable<Comparable<?>>)v2;
			else
				return 0;
			
			if(sort.isDesc())
				return c2.compareTo(c1);
			else
				return c1.compareTo(c2);
		} catch (SecurityException | IllegalArgumentException | 
				IllegalAccessException | InvocationTargetException | 
				NoSuchMethodException e) {
			LOG.warn(e.getMessage(),e);
			return 0;
		}
	}
	

}
