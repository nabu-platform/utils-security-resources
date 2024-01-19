package be.nabu.utils.security.resources;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import be.nabu.libs.resources.api.ReadableResource;
import be.nabu.libs.resources.api.Resource;
import be.nabu.libs.resources.api.WritableResource;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.io.api.WritableContainer;
import be.nabu.utils.security.resources.KeyStoreManagerConfiguration.KeyStoreConfiguration;

public class ResourceConfigurationHandler implements KeyStoreConfigurationHandler {

	private Resource resource;
	private Class<? extends KeyStoreConfiguration> configurationClass;

	public ResourceConfigurationHandler(Resource resource) {
		this(resource, KeyStoreConfiguration.class);
	}
	
	public ResourceConfigurationHandler(Resource resource, Class<? extends KeyStoreConfiguration> configurationClass) {
		this.resource = resource;
		this.configurationClass = configurationClass;
	}
		
	@Override
	public void save(KeyStoreConfiguration configuration) throws IOException {
		try {
			marshal(configuration, (WritableResource) resource);
		}
		catch (JAXBException e) {
			throw new IOException(e);
		}
	}
	
	public void marshal(KeyStoreConfiguration configuration, OutputStream container) throws JAXBException {
		JAXBContext context = JAXBContext.newInstance(configurationClass);
		Marshaller marshaller = context.createMarshaller();
		marshaller.marshal(configuration, container);
	}
	
	public void marshal(KeyStoreConfiguration configuration, WritableResource resource) throws IOException, JAXBException {
		WritableContainer<ByteBuffer> output = resource.getWritable();
		try {
			marshal(configuration, IOUtils.toOutputStream(output));
		}
		finally {
			output.close();
		}
	}
	
	// currently unused, if we delete the deprecated, we can rename these before using them
	// older servers (like wauters) had a dependency to it @2023-12-11
	KeyStoreConfiguration unmarshalLocal(InputStream input) throws JAXBException {
		return unmarshal(input, configurationClass);
	}
	KeyStoreConfiguration unmarshalLocal(ReadableResource resource) throws IOException, JAXBException {
		ReadableContainer<ByteBuffer> data = resource.getReadable();
		try {
			return unmarshal(IOUtils.toInputStream(data), configurationClass);
		}
		finally {
			data.close();
		}
	}
	
	public static KeyStoreConfiguration unmarshal(InputStream input, Class<?> configurationClass) throws JAXBException {
		JAXBContext context = JAXBContext.newInstance(configurationClass);
		Unmarshaller unmarshaller = context.createUnmarshaller();
		return (KeyStoreConfiguration) unmarshaller.unmarshal(input);
	}

	// currently retained for backwards compatibility
	@Deprecated
	public static KeyStoreConfiguration unmarshal(InputStream input) throws JAXBException {
		return unmarshal(input, KeyStoreConfiguration.class);
	}
	@Deprecated
	public static KeyStoreConfiguration unmarshal(ReadableResource resource) throws IOException, JAXBException {
		ReadableContainer<ByteBuffer> data = resource.getReadable();
		try {
			return unmarshal(IOUtils.toInputStream(data));
		}
		finally {
			data.close();
		}
	}
}
