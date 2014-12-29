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

	public ResourceConfigurationHandler(Resource resource) {
		this.resource = resource;
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
		JAXBContext context = JAXBContext.newInstance(KeyStoreConfiguration.class);
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
	
	public static KeyStoreConfiguration unmarshal(InputStream input) throws JAXBException {
		JAXBContext context = JAXBContext.newInstance(KeyStoreConfiguration.class);
		Unmarshaller unmarshaller = context.createUnmarshaller();
		return (KeyStoreConfiguration) unmarshaller.unmarshal(input);
	}
	
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
