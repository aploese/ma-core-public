/**
 * Copyright (C) 2015 Infinite Automation Software. All rights reserved.
 * @author Terry Packer
 */
package com.serotonin.m2m2.web.mvc.rest.v1.mapping;

import java.io.IOException;
import java.util.List;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.serotonin.m2m2.module.ModelDefinition;
import com.serotonin.m2m2.module.ModuleRegistry;
import com.serotonin.m2m2.web.mvc.rest.v1.exception.ModelNotFoundException;
import com.serotonin.m2m2.web.mvc.rest.v1.model.dataPoint.PointLocatorModel;


/**
 * @author Terry Packer
 *
 */
public class PointLocatorModelDeserializer extends StdDeserializer<PointLocatorModel<?>>{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	

	/**
	 * 
	 */
	protected PointLocatorModelDeserializer() {
		super(PointLocatorModel.class);
	}

	/* (non-Javadoc)
	 * @see com.fasterxml.jackson.databind.JsonDeserializer#deserialize(com.fasterxml.jackson.core.JsonParser, com.fasterxml.jackson.databind.DeserializationContext)
	 */
	@Override
	public PointLocatorModel<?> deserialize(JsonParser jp,
			DeserializationContext ctxt) throws IOException,
			JsonProcessingException {
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();  
		JsonNode tree = jp.readValueAsTree();
	    ModelDefinition definition = findModelDefinition(tree.get("modelType").asText());
	    return (PointLocatorModel<?>) mapper.treeToValue(tree, definition.getModelClass());
	}

	/**
	 * @return
	 */
	public ModelDefinition findModelDefinition(String typeName) throws ModelNotFoundException{
		List<ModelDefinition> definitions = ModuleRegistry.getModelDefinitions();
		for(ModelDefinition definition : definitions){
			if(definition.getModelTypeName().equalsIgnoreCase(typeName))
				return definition;
		}
		throw new ModelNotFoundException(typeName);
	}




}
