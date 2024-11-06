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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBException;

import be.nabu.libs.resources.ResourceFactory;
import be.nabu.libs.resources.ResourceUtils;
import be.nabu.libs.resources.URIUtils;
import be.nabu.libs.resources.api.ManageableContainer;
import be.nabu.libs.resources.api.ReadableResource;
import be.nabu.libs.resources.api.Resource;
import be.nabu.libs.resources.api.WritableResource;
import be.nabu.utils.io.ContentTypeMap;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.io.api.WritableContainer;
import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.SecurityRuntimeException;
import be.nabu.utils.security.StoreType;
import be.nabu.utils.security.api.KeyStoreManager;
import be.nabu.utils.security.api.ManagedKeyStore;
import be.nabu.utils.security.resources.KeyStoreManagerConfiguration.KeyStoreConfiguration;

/**
 * This allows you to manage multiple keystores and store settings like passwords etc
 * 
 * @author alex
 *
 */
public class KeyStoreManagerImpl implements KeyStoreManager, KeyStoreConfigurationHandler {
	
	private KeyStoreManagerConfiguration configuration;
	
	private Map<String, ManagedKeyStoreImpl> keystores = new HashMap<String, ManagedKeyStoreImpl>();
	
	private Principal accessPrincipal;
	
	private ReadableResource resource;
	
	private ResourceFactory resourceFactory;
	
	public static KeyStoreManagerImpl getManager(ManageableContainer<?> parent, String configurationName) throws IOException {
		WritableResource resource = (WritableResource) parent.getChild(configurationName);
		if (resource == null)
			resource = (WritableResource) parent.create(configurationName, ContentTypeMap.getInstance().getContentTypeFor(configurationName));
		try {
			new KeyStoreManagerConfiguration().marshal(resource);
		}
		catch (JAXBException e) {
			throw new RuntimeException(e);
		}
		return new KeyStoreManagerImpl((ReadableResource) resource);
	}
	
	public KeyStoreManagerImpl(ReadableResource resource) throws IOException {
		try {
			this.configuration = KeyStoreManagerConfiguration.unmarshal(resource);
		}
		catch (JAXBException e) {
			throw new IllegalArgumentException("The resource does not point to a valid configuration", e);
		}
		this.resource = resource;
	}
	
	public List<String> listKeystores() {
		List<String> list = new ArrayList<String>();
		for (KeyStoreConfiguration keystoreConfiguration : configuration.getKeyStores())
			list.add(keystoreConfiguration.getAlias());
		return list;
	}
	
	public KeyStoreConfiguration getKeyStoreConfiguration(String alias) {
		for (KeyStoreConfiguration keystoreConfiguration : configuration.getKeyStores()) {
			if (keystoreConfiguration.getAlias().equals(alias))
				return keystoreConfiguration;
		}
		return null;
	}
	
	void saveConfiguration() throws IOException {
		if (resource instanceof WritableResource) {
			try {
				configuration.marshal((WritableResource) resource);
			}
			catch (JAXBException e) {
				throw new RuntimeException(e);
			}
		}
	}
	
	@Override
	public ManagedKeyStoreImpl getKeyStore(String alias) throws IOException {
		if (!keystores.containsKey(alias)) {
			ManagedKeyStoreImpl implementation = null;
			for (KeyStoreConfiguration keystoreConfiguration : configuration.getKeyStores()) {
				if (keystoreConfiguration.getAlias().equals(alias)) {
					KeyStoreHandler handler = null;
					Resource resource = getResourceFactory().resolve(keystoreConfiguration.getUri(), accessPrincipal);
					try {
						// create if it doesn't exist
						if (resource == null) {
							Resource parent = ResourceUtils.mkdir(URIUtils.getParent(keystoreConfiguration.getUri()), accessPrincipal);
							if (parent == null)
								throw new IOException("Can not find or create parent of " + keystoreConfiguration.getUri());
							StoreType storeType = StoreType.findByContentType(ContentTypeMap.getInstance().getContentTypeFor(keystoreConfiguration.getUri().getPath()));
							if (storeType == null)
								throw new IllegalArgumentException("Could not determine the store type of " + keystoreConfiguration.getUri());
							resource = ((ManageableContainer<?>) parent).create(URIUtils.getName(keystoreConfiguration.getUri()), storeType.getContentType());
							if (!(resource instanceof WritableResource))
								throw new IOException("The resource at " + keystoreConfiguration.getUri() + " is not writable");
							handler = KeyStoreHandler.create(keystoreConfiguration.getPassword(), storeType);
							// do an initial save to store it in its empty state, otherwise there is a file with 0 bytes which will not be parseable upon a next run
							WritableContainer<ByteBuffer> output = ((WritableResource) resource).getWritable();
							try {
								handler.save(IOUtils.toOutputStream(output), keystoreConfiguration.getPassword());
							}
							finally {
								output.close();
							}
						}
						else if (!(resource instanceof ReadableResource))
							throw new IOException("The resource at " + keystoreConfiguration.getUri() + " is not readable");
						else {
							ReadableContainer<ByteBuffer> input = ((ReadableResource) resource).getReadable();
							try {
								handler = KeyStoreHandler.load(IOUtils.toInputStream(input), keystoreConfiguration.getPassword(), StoreType.JKS);
							}
							finally {
								input.close();
							}
						}
						implementation = new ManagedKeyStoreImpl(this, resource, keystoreConfiguration, handler);
						break;
					}
					catch (NoSuchAlgorithmException e) {
						throw new SecurityRuntimeException(e);
					}
					catch (CertificateException e) {
						throw new SecurityRuntimeException(e);
					} 
					catch (KeyStoreException e) {
						throw new SecurityRuntimeException(e);
					}
					catch (NoSuchProviderException e) {
						throw new SecurityRuntimeException(e);
					}
				}
			}
			if (implementation != null)
				keystores.put(alias, implementation);
		}
		return keystores.get(alias);
	}
	
	public ResourceFactory getResourceFactory() {
		if (resourceFactory == null)
			resourceFactory = ResourceFactory.getInstance();
		return resourceFactory;
	}

	public void setResourceFactory(ResourceFactory resourceFactory) {
		this.resourceFactory = resourceFactory;
	}

	@Override
	public ManagedKeyStore createKeyStore(String alias, String password, StoreType type) throws IOException {
		if (!(resource.getParent() instanceof ManageableContainer))
			throw new IOException("Can not create keystores");

		ManagedKeyStore existing = getKeyStore(alias);
		if (existing != null)
			throw new IllegalArgumentException("A keystore with this alias already exists: " + alias);
		
		KeyStoreConfiguration newKeyStore = new KeyStoreConfiguration();
		newKeyStore.setAlias(alias);
		newKeyStore.setPassword(password);
		newKeyStore.setUri(URIUtils.getChild(
			URIUtils.getParent(ResourceUtils.getURI(resource)),
			alias + "." + ContentTypeMap.getInstance().getExtensionFor(type.getContentType())
		));
		
		configuration.getKeyStores().add(newKeyStore);
		saveConfiguration();
		
		// it will be automatically created by this method
		return getKeyStore(alias);
	}

	public Principal getAccessPrincipal() {
		return accessPrincipal;
	}

	public void setAccessPrincipal(Principal accessPrincipal) {
		this.accessPrincipal = accessPrincipal;
	}

	@Override
	public void deleteKeyStore(String alias) throws IOException {
		Iterator<KeyStoreConfiguration> iterator = configuration.getKeyStores().iterator();
		while (iterator.hasNext()) {
			KeyStoreConfiguration keystoreConfiguration = iterator.next();
			if (keystoreConfiguration.getAlias().equals(alias)) {
				// delete the actual resource if any
				Resource resource = getResourceFactory().resolve(keystoreConfiguration.getUri(), accessPrincipal);
				if (resource != null) {
					if (!(resource.getParent() instanceof ManageableContainer))
						throw new IOException("Can not delete " + keystoreConfiguration.getUri());
					((ManageableContainer<?>) resource.getParent()).delete(URIUtils.getName(keystoreConfiguration.getUri()));
				}
				// delete the configuration option
				iterator.remove();
				// save the changes to config
				saveConfiguration();
				// delete the cached keystore (if any)
				keystores.remove(alias);
				break;
			}
		}
	}

	public KeyStoreManagerConfiguration getConfiguration() {
		return configuration;
	}

	@Override
	public void save(KeyStoreConfiguration keystore) throws IOException {
		boolean found = false;
		for (int i = 0; i < configuration.getKeyStores().size(); i++) {
			if (configuration.getKeyStores().get(i).getAlias().equals(keystore.getAlias())) {
				configuration.getKeyStores().set(i, keystore);
				found = true;
				break;
			}
		}
		if (!found) {
			configuration.getKeyStores().add(keystore);
		}
		saveConfiguration();
	}
}
