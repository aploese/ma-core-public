<%--
    Copyright (C) 2014 Infinite Automation Systems Inc. All rights reserved.
    @author Matthew Lohbihler
--%>
<%@page import="com.serotonin.m2m2.vo.DataPointVO"%>
<%@ include file="/WEB-INF/jsp/include/tech.jsp"%>
<%@page import="com.serotonin.m2m2.DataTypes"%>

<script type="text/javascript">
	//Create a filter select list
	var unitsMasterListStore;
	var unitPicker, renderedUnitPicker, integralUnitPicker;

	require([ "dojo", "dojo/store/Memory", "dijit/form/ComboBox" ], function(
			dojo, Memory, ComboBox) {

		//Go get the units list
		DataPointDwr.getUnitsList(function(response) {
			//Create the store
			unitsMasterListStore = new dojo.store.Memory({
				idProperty : "key",
				valueProperty : "value",
				data : response.data.units
			});

			//Create the base unit input
			unitPicker = new ComboBox({
				store : unitsMasterListStore,
				autoComplete : false,
				style : "width: 250px;",
				queryExpr : "*\${0}*",
				highlightMatch : "all",
				required : false,
				placeHolder : "select unit",
				onChange : function(unit) {
					validateUnit(unit, 'unitMessage');
				}
			}, "unit");

			//Create the base unit input
			renderedUnitPicker = new ComboBox({
				store : unitsMasterListStore,
				autoComplete : false,
				style : "width: 250px;",
				queryExpr : "*\${0}*",
				highlightMatch : "all",
				required : false,
				placeHolder : "select unit",
				onChange : function(unit) {
					validateUnit(unit, 'renderedUnitMessage');
				}
			}, "renderedUnit");

			//Create the base unit input
			integralUnitPicker = new ComboBox({
				store : unitsMasterListStore,
				autoComplete : false,
				style : "width: 250px;",
				queryExpr : "*\${0}*",
				highlightMatch : "all",
				required : false,
				placeHolder : "select unit",
				onChange : function(unit) {
					validateUnit(unit, 'integralUnitMessage');
				}
			}, "integralUnit");
		});

	});

	/**
	 * Set the input values on the page using this vo
	 */
	function setPointProperties(vo) {

		var useIntegralUnit = dijit.byId('useIntegralUnit');

		useIntegralUnit.watch('checked', function(value) {
			if (useIntegralUnit.checked) {
				show("integralUnitSection");
			} else {
				hide("integralUnitSection");
			}
		});

		var useRenderedUnit = dijit.byId('useRenderedUnit');
		var renderedUnit = dojo.byId('renderedUnit');
		useRenderedUnit.watch('checked', function(value) {
			if (useRenderedUnit.checked) {
				show("renderedUnitSection");
			} else {
				hide("renderedUnitSection");
			}
		});

		//Set all necessary values
		//dojo.byId("unit").value = vo.unitString;
		unitPicker.set('value', vo.unitString);
		//dojo.byId("renderedUnit").value = vo.renderedUnitString;
		renderedUnitPicker.set('value', vo.renderedUnitString);
		//dojo.byId("integralUnit").value = vo.integralUnitString;
		integralUnitPicker.set('value', vo.integralUnitString);

		//Not sure why the watch isn't working
		useRenderedUnit.set('checked', vo.useRenderedUnit);
		if (vo.useRenderedUnit)
			show("renderedUnitSection");
		else
			hide("renderedUnitSection");

		useIntegralUnit.set('checked', vo.useIntegralUnit);
		if (vo.useIntegralUnit)
			show("integralUnitSection");
		else
			hide("integralUnitSection");

		dojo.byId("chartColour").value = vo.chartColour;
		dojo.byId("plotType").value = vo.plotType;

		if (vo.pointLocator.dataTypeId == <%=DataTypes.NUMERIC%>) {
			show("unitSection");
		} else {
			$("plotType").disabled = true;
			$set("plotType",<%=DataPointVO.PlotTypes.STEP%>);
		}

	}

	/*
	 * Get the values and put into the vo
	 */
	function getPointProperties(vo) {
		vo.unitString = unitPicker.get('value'); //dojo.byId("unit").value;
		vo.renderedUnitString = renderedUnitPicker.get('value'); //dojo.byId("renderedUnit").value;
		vo.integralUnitString = integralUnitPicker.get('value'); //dojo.byId("integralUnit").value;
		vo.useRenderedUnit = dijit.byId("useRenderedUnit").get('checked');
		vo.useIntegralUnit = dijit.byId("useIntegralUnit").get('checked');

		vo.chartColour = dojo.byId("chartColour").value;
		vo.plotType = dojo.byId("plotType").value;
	}

	/**
	 * Helper method to validate units on demand
	 */
	function validateUnit(unitString, messageDivId) {
		DataPointDwr.validateUnit(unitString, function(response) {
			if (!response.data.validUnit) {
				var div = $(messageDivId);
				div.style.color = "red";
				div.innerHTML = response.data.message;
			} else {
				var div = $(messageDivId);
				div.style.color = "green";
				div.innerHTML = response.data.message;
			}
		});
	}

	/**
	 * Reset the Point Properties Inputs depending on Data Type
	 */
	function resetPointProperties(dataTypeId) {
		if (dataTypeId == <%=DataTypes.NUMERIC%>) {
			show("unitSection");
			$("plotType").disabled = false;
		} else {
			hide("unitSection");
			$("plotType").disabled = true;
			$set("plotType",<%=DataPointVO.PlotTypes.STEP%>);
		}
	}
	//Register for callbacks when the data type is changed
	dataTypeChangedCallbacks.push(resetPointProperties);

	function disablePointProperties(dataTypeId) {
		setDisabled('chartColour', true);
		setDisabled('plotType', true);
	}
	
	function enablePointProperties(dataTypeId) {
		setDisabled('chartColour', false);
		setDisabled('plotType', false);
		resetPointProperties(dataTypeId);
	}
</script>

<div>
  <table>
    <tr>
      <td colspan="3"><span class="smallTitle"><fmt:message
            key="pointEdit.props.props" /></span> <tag:help
          id="dataPointEditing" /></td>
    </tr>

    <tbody id="unitSection" style="display: none;">
      <tr>
        <td class="formLabel"><fmt:message
            key="pointEdit.props.unit" /></td>
        <td class="formField">
          <div id="unit"></div>
          <div id="unitMessage"></div>
        </td>
      </tr>
      <tr>
        <td class="formLabel"><fmt:message
            key="pointEdit.props.useRenderedUnit" /></td>
        <td class="formField"><input
          data-dojo-type="dijit.form.CheckBox" id="useRenderedUnit"
          name="useRenderedUnit" /></td>
      </tr>
      <tr id="renderedUnitSection">
        <td class="formLabelRequired"><fmt:message
            key="pointEdit.props.renderedUnit" /></td>
        <td class="formField">
          <div id="renderedUnit"></div>
          <div id="renderedUnitMessage"></div>
        </td>
      </tr>
      <tr>
        <td class="formLabel"><fmt:message
            key="pointEdit.props.useIntegralUnit" /></td>
        <td class="formField"><input
          data-dojo-type="dijit.form.CheckBox" id="useIntegralUnit"
          name="useIntegralUnit" /></td>
      </tr>
      <tr id="integralUnitSection">
        <td class="formLabelRequired"><fmt:message
            key="pointEdit.props.integralUnit" /></td>
        <td class="formField">
          <div id="integralUnit"></div>
          <div id="integralUnitMessage"></div>
        </td>
      </tr>
    </tbody>

    <tr>
      <td class="formLabelRequired"><fmt:message
          key="pointEdit.props.chartColour" /></td>
      <td class="formField"><input type="text" name="chartColour"
        id="chartColour" /></td>
    </tr>

    <tr>
      <td class="formLabelRequired"><fmt:message
          key="pointEdit.plotType" /></td>
      <td class="formField"><sst:select name="plotType"
          id="plotType">
          <sst:option
            value="<%=Integer.toString(DataPointVO.PlotTypes.STEP)%>">
            <fmt:message key="pointEdit.plotType.step" />
          </sst:option>
          <sst:option
            value="<%=Integer.toString(DataPointVO.PlotTypes.LINE)%>">
            <fmt:message key="pointEdit.plotType.line" />
          </sst:option>
          <sst:option
            value="<%=Integer.toString(DataPointVO.PlotTypes.SPLINE)%>">
            <fmt:message key="pointEdit.plotType.spline" />
          </sst:option>
        </sst:select></td>
    </tr>
  </table>
</div>