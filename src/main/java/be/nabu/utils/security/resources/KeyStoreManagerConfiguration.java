/*
* Copyright (C) 2014 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.utils.security.resources;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import be.nabu.libs.resources.api.ReadableResource;
import be.nabu.libs.resources.api.WritableResource;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.io.api.WritableContainer;
import be.nabu.utils.security.EncryptionXmlAdapter;
import be.nabu.utils.security.StoreType;

@XmlRootElement(name="keystoreManager")
public class KeyStoreManagerConfiguration {
	
	private URI newKeystoreContainer;
	
	private List<KeyStoreConfiguration> keyStores = new ArrayList<KeyStoreConfiguration>();

	public List<KeyStoreConfiguration> getKeyStores() {
		return keyStores;
	}

	public void setKeyStores(List<KeyStoreConfiguration> handlers) {
		this.keyStores = handlers;
	}
	
	public URI getNewKeystoreContainer() {
		return newKeystoreContainer;
	}

	public void setNewKeystoreContainer(URI newKeystoreContainer) {
		this.newKeystoreContainer = newKeystoreContainer;
	}

	public static class AliasPasswordAdapter extends XmlAdapter<AliasPasswordEntry [], Map<String, String>> {

		@Override
		public HashMap<String, String> unmarshal(AliasPasswordEntry [] arg0) throws Exception {
			HashMap<String, String> values = new HashMap<String, String>();
			for (AliasPasswordEntry entry : arg0)
				values.put(entry.getAlias(), entry.getPassword());
			return values;
		}

		@Override
		public AliasPasswordEntry [] marshal(Map<String, String> arg0) throws Exception {
			AliasPasswordEntry [] values = new AliasPasswordEntry[arg0.size()];
			int i = 0;
			for (String key : arg0.keySet()) {
				AliasPasswordEntry value = new AliasPasswordEntry();
				value.setAlias(key);
				value.setPassword(arg0.get(key));
				values[i++] = value;
			}
			return values;
		}
	}
	
	public static class AliasPasswordEntry {
		private String alias, password;

		public String getAlias() {
			return alias;
		}

		public void setAlias(String alias) {
			this.alias = alias;
		}

		@XmlJavaTypeAdapter(value=EncryptionXmlAdapter.class)
		public String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			this.password = password;
		}
	}

	// for older servers (only one client currently) which can not be update, this annotation has to be active, otherwise the discrepancy between the old keystore module on the server and the new developer means you can't open keystores
	// however, for newer servers, if we enable this, the extension (added in a later update) has the _same_ root element as this one. this conflict means it can choose the wrong class (which it seemingly does without hesitation) which leads to classcast exceptions
	// so we need to keep this disabled
//	@XmlRootElement(name = "keystore")
	public static class KeyStoreConfiguration {

		private URI uri;
		private String alias;
		private String password;
		private StoreType type;
		
		/**
		 * All the passwords for the private keys (null or non-existent if no password)
		 */
		private Map<String, String> keyPasswords = new HashMap<String, String>();
		
		public String getAlias() {
			return alias;
		}
		public void setAlias(String alias) {
			this.alias = alias;
		}
		
		@XmlJavaTypeAdapter(value=EncryptionXmlAdapter.class)
		public String getPassword() {
			return password;
		}
		
		public void setPassword(String password) {
			this.password = password;
		}
		
		@XmlJavaTypeAdapter(value=AliasPasswordAdapter.class)
		public Map<String, String> getKeyPasswords() {
			return keyPasswords;
		}
		
		public void setKeyPasswords(Map<String, String> keyPasswords) {
			this.keyPasswords = keyPasswords;
		}

		public URI getUri() {
			return uri;
		}
		public void setUri(URI uri) {
			this.uri = uri;
		}
		
		public StoreType getType() {
			return type;
		}
		public void setType(StoreType type) {
			this.type = type;
		}
		
	}
	
	public static KeyStoreManagerConfiguration unmarshal(InputStream input) throws JAXBException {
		JAXBContext context = JAXBContext.newInstance(KeyStoreManagerConfiguration.class);
		Unmarshaller unmarshaller = context.createUnmarshaller();
		return (KeyStoreManagerConfiguration) unmarshaller.unmarshal(input);
	}
	
	public static KeyStoreManagerConfiguration unmarshal(ReadableResource resource) throws IOException, JAXBException {
		ReadableContainer<ByteBuffer> data = resource.getReadable();
		try {
			return unmarshal(IOUtils.toInputStream(data));
		}
		finally {
			data.close();
		}
	}
	
	public void marshal(OutputStream container) throws JAXBException {
		JAXBContext context = JAXBContext.newInstance(KeyStoreManagerConfiguration.class);
		Marshaller marshaller = context.createMarshaller();
		marshaller.marshal(this, container);
	}
	
	public void marshal(WritableResource resource) throws IOException, JAXBException {
		WritableContainer<ByteBuffer> output = resource.getWritable();
		try {
			marshal(IOUtils.toOutputStream(output));
		}
		finally {
			output.close();
		}
	}
}
