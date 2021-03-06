/*
    Copyright (C) 2014 Infinite Automation Systems Inc. All rights reserved.
    @author Matthew Lohbihler
 */
package com.serotonin.m2m2.view.chart;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Map;

import com.serotonin.json.spi.JsonProperty;
import com.serotonin.m2m2.Common;
import com.serotonin.m2m2.DataTypes;
import com.serotonin.m2m2.i18n.ProcessResult;
import com.serotonin.m2m2.rt.dataImage.DataPointRT;
import com.serotonin.m2m2.view.ImplDefinition;
import com.serotonin.m2m2.vo.DataPointVO;

/**
 * @author Matthew Lohbihler
 */
public class ImageFlipbookRenderer extends BaseChartRenderer {
    private static ImplDefinition definition = new ImplDefinition("chartRendererImageFlipbook", "FLIPBOOK",
            "chartRenderer.flipbook", new int[] { DataTypes.IMAGE });

    public static ImplDefinition getDefinition() {
        return definition;
    }

    @Override
    public String getTypeName() {
        return definition.getName();
    }

    @JsonProperty
    private int limit;

    public ImageFlipbookRenderer() {
        // no op
    }

    public ImageFlipbookRenderer(int limit) {
        this.limit = limit;
    }

    public int getLimit() {
        return limit;
    }

    public void setLimit(int limit) {
        this.limit = limit;
    }

    @Override
    public void addDataToModel(Map<String, Object> model, DataPointVO point) {
        DataPointRT rt = Common.runtimeManager.getDataPoint(point.getId());
        if (rt != null)
            model.put("chartData", rt.getLatestPointValues(limit));
    }

    @Override
    public ImplDefinition getDef() {
        return definition;
    }

    @Override
    public String getChartSnippetFilename() {
        return "flipbookChart.jsp";
    }

    //
    // /
    // / Serialization
    // /
    //
    private static final long serialVersionUID = -1;
    private static final int version = 1;

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeInt(version);
        out.writeInt(limit);
    }

    private void readObject(ObjectInputStream in) throws IOException {
        int ver = in.readInt();

        // Switch on the version of the class so that version changes can be elegantly handled.
        if (ver == 1) {
            limit = in.readInt();
        }
    }
    
	/* (non-Javadoc)
	 * @see com.serotonin.m2m2.view.chart.ChartRenderer#validate(com.serotonin.m2m2.i18n.ProcessResult)
	 */
	@Override
	public void validate(ProcessResult result) {
		
		if((limit < 2)||(limit>50))
			result.addContextualMessage("limit", "pointEdit.chart.invalidLimit");
		
	}
    
    
}
