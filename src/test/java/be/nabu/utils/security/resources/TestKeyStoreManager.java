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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import be.nabu.libs.resources.ResourceUtils;
import be.nabu.libs.resources.api.ManageableContainer;
import be.nabu.libs.resources.api.ReadableResource;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.security.BCSecurityUtils;
import be.nabu.utils.security.KeyPairType;
import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.SecurityUtils;
import be.nabu.utils.security.StoreType;
import be.nabu.utils.security.api.KeyStoreManager;
import be.nabu.utils.security.api.ManagedKeyStore;

public class TestKeyStoreManager extends TestCase {

	public void testGeneral() throws URISyntaxException, NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, NoSuchProviderException, UnrecoverableKeyException {
		ManageableContainer<?> target = (ManageableContainer<?>) ResourceUtils.mkdir(new URI("memory:/test/keystore"), null);
		
		KeyStoreManager keystoreManager = KeyStoreManagerImpl.getManager(target, "configuration.xml");
		assertEquals(0, keystoreManager.listKeystores().size());
		
		// create new keystore
		ManagedKeyStore keystore = keystoreManager.createKeyStore("My Keystore", "testpassword", StoreType.JKS);
		assertNotNull(keystore);
		assertEquals(1, keystoreManager.listKeystores().size());
		assertEquals(keystore, keystoreManager.getKeyStore("My Keystore"));
		
		// generate a new keypair for the server
		KeyPair pair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 1024);
		X500Principal serverPrincipal = SecurityUtils.createX500Principal("server", null, null, null, null, null);
		// self sign for server
		X509Certificate ca = BCSecurityUtils.generateSelfSignedCertificate(pair, new Date(new Date().getTime() + 1000*60*60*24), 
			serverPrincipal, 
			serverPrincipal
		);		
		// add the private key + self signed certificate to the keystore
		keystore.set("ca", ca);
		keystore.set("ca-key", pair.getPrivate(), new X509Certificate[] { ca }, "testpassword");
		
		assertEquals(ca, keystore.getCertificate("ca"));
		assertEquals(pair.getPrivate(), keystore.getPrivateKey("ca-key"));
		
		// load the keystore independent of the manager to verify that it is written correctly
		KeyStoreHandler customHandler = KeyStoreHandler.load(
			IOUtils.toInputStream(ResourceUtils.toReadableContainer(((KeyStoreManagerImpl) keystoreManager).getKeyStore("My Keystore").getConfiguration().getUri(), null)),
			"testpassword", StoreType.JKS);
		assertEquals(ca, customHandler.getCertificate("ca"));
		assertEquals(pair.getPrivate(), customHandler.getPrivateKey("ca-key", "testpassword"));
		
		// double check that the saved passwords are indeed encrypted
		String configuration = new String(IOUtils.toBytes(((ReadableResource) target.getChild("configuration.xml")).getReadable()));
		// the password we entered above should not be visible in plain text in the configuration
		// by default it is encrypted into the form ${encrypted:<base64>}
		assertTrue(configuration.indexOf("testpassword") == -1);
	}

}
