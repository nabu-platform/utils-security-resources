package be.nabu.utils.security.resources;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

import be.nabu.libs.resources.api.Resource;
import be.nabu.libs.resources.api.WritableResource;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.WritableContainer;
import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.api.ManagedKeyStore;
import be.nabu.utils.security.resources.KeyStoreManagerConfiguration.KeyStoreConfiguration;

public class ManagedKeyStoreImpl implements ManagedKeyStore {
	
	private KeyStoreHandler handler;
	private KeyStoreManagerImpl manager;
	private KeyStoreConfiguration configuration;
	private Resource resource;
	
	ManagedKeyStoreImpl(KeyStoreManagerImpl manager, Resource resource, KeyStoreConfiguration configuration, KeyStoreHandler handler) {
		this.handler = handler;
		this.configuration = configuration;
		this.manager = manager;
		this.resource = resource;
	}
	
	public void set(String alias, X509Certificate certificate) throws KeyStoreException, IOException {
		handler.set(alias, certificate);
		// save the keystore
		save();
	}
	
	@Override
	public void set(String alias, SecretKey secretKey, String password) throws KeyStoreException, IOException {
		// add to keystore
		handler.set(alias, secretKey, password);
		// save the keystore
		save();
		// add password to configuration
		configuration.getKeyPasswords().put(alias, password);
		// store the configuration
		manager.saveConfiguration();
	}

	@Override
	public void set(String alias, PrivateKey privateKey, X509Certificate [] chain, String password) throws KeyStoreException, IOException {
		// add to keystore
		handler.set(alias, privateKey, chain, password);
		// save the keystore
		save();
		// add password to configuration
		configuration.getKeyPasswords().put(alias, password);
		// store the configuration
		manager.saveConfiguration();
	}
	
	@Override
	public void rename(String oldAlias, String newAlias) throws KeyStoreException, IOException {
		try {
			handler.rename(oldAlias, newAlias, configuration.getKeyPasswords().get(oldAlias));
		}
		catch (UnrecoverableKeyException e) {
			throw new KeyStoreException(e);
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		save();
	}
	
	public String getPassword() {
		return configuration.getPassword();
	}
	
	public String getPassword(String alias) {
		return configuration.getKeyPasswords().get(alias);
	}
	
	@Override
	public void delete(String alias) throws KeyStoreException, IOException {
		handler.delete(alias);
		save();
		// check if there was a password for this alias, delete it if necessary
		if (configuration.getKeyPasswords().containsKey(alias)) {
			configuration.getKeyPasswords().remove(alias);
			manager.saveConfiguration();
		}
	}
	
	@Override
	public PrivateKey getPrivateKey(String alias) throws KeyStoreException {
		try {
			return handler.getPrivateKey(alias, configuration.getKeyPasswords().get(alias));
		}
		catch (UnrecoverableKeyException e) {
			throw new KeyStoreException(e);
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public X509Certificate getCertificate(String alias) throws KeyStoreException {
		return handler.getCertificate(alias);
	}
	
	@Override
	public SecretKey getSecretKey(String alias) throws KeyStoreException {
		try {
			return handler.getSecretKey(alias, configuration.getKeyPasswords().get(alias));
		}
		catch (UnrecoverableKeyException e) {
			throw new KeyStoreException(e);
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public void save() throws IOException {
		if (resource instanceof WritableResource) {
			WritableContainer<ByteBuffer> output = ((WritableResource) resource).getWritable();
			try {
				try {
					handler.save(IOUtils.toOutputStream(output), configuration.getPassword());
				}
				finally {
					output.close();
				}
			}
			catch (KeyStoreException e) {
				throw new RuntimeException(e);
			}
			catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
			catch (CertificateException e) {
				throw new RuntimeException(e);
			}
		}
	}

	@Override
	public X509Certificate[] getChain(String alias) throws KeyStoreException {
		Certificate [] chain = handler.getKeyStore().getCertificateChain(alias);
		X509Certificate [] certificates = new X509Certificate[chain.length];
		for (int i = 0; i < chain.length; i++)
			certificates[i] = (X509Certificate) chain[i];
		return certificates;
	}

	@Override
	public KeyStore getKeyStore() {
		return handler.getKeyStore();
	}
	
	public KeyStoreConfiguration getConfiguration() {
		return configuration;
	}
}