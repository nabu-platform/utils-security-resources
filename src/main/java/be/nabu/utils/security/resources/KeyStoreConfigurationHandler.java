package be.nabu.utils.security.resources;

import java.io.IOException;

import be.nabu.utils.security.resources.KeyStoreManagerConfiguration.KeyStoreConfiguration;

public interface KeyStoreConfigurationHandler {
	public void save(KeyStoreConfiguration configuration) throws IOException;
}
