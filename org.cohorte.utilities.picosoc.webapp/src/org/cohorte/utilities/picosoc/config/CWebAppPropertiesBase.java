package org.cohorte.utilities.picosoc.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map.Entry;
import java.util.Properties;

import org.cohorte.utilities.IXResourceLocator;
import org.cohorte.utilities.picosoc.CAbstractComponentWithLogger;
import org.cohorte.utilities.encode.CBase64Decoder;
import org.cohorte.utilities.encode.IBase64;
import org.psem2m.utilities.CXBytesUtils;
import org.psem2m.utilities.files.CXFileDir;

/**
 *
 * Config file modelisation
 *
 * Use two files
 *
 *
 * <ul>
 * <li>myConfigName.base.properties.xml
 * <li>myConfigName.properties.xml
 * </ul>
 *
 * @author ogattaz
 *
 */
public abstract class CWebAppPropertiesBase extends
		CAbstractComponentWithLogger implements ISvcWebAppProperties {

	public static final String PROPERTIES_BASE_XML = ".base.properties.xml";
	public static final String PROPERTIES_XML = ".properties.xml";

	private final CXFileDir pConfigDir;
	private final String pConfigName;
	private final Properties pProperties = new Properties();
	private final ClassLoader pResourceLoader;
	private final String pResourcePath;

	/**
	 * @param aConfigDir
	 *            le location of the config files
	 * @param aConfigName
	 *            the prefix of the nbame of the confif files
	 * @param aResourceLoaderClass
	 *            aClass giving the package path and the classloader allowing
	 *            the loadeing of the models of the config files
	 * @throws IOException
	 */
	public CWebAppPropertiesBase(final File aConfigDir,
			final String aConfigName, final IXResourceLocator aResourceLocator)
			throws IOException {
		super();

		pConfigDir = new CXFileDir(aConfigDir);
		pConfigName = aConfigName;
		pResourcePath = aResourceLocator.getResourcePackage().getName()
				.replace('.', '/');
		pResourceLoader = aResourceLocator.getResourceLoader();

		init();

		registerMeAsService(ISvcWebAppProperties.class);

		getLogger().logInfo(this, "<init>", "instanciated %s", this);
	}

	/**
	 * @param aSB
	 * @return
	 */
	protected StringBuilder addDescriptionInSB(final StringBuilder aSB) {

		return aSB;
	}

	/**
	 * extract value from an encoded one
	 *
	 * <pre>
	 * fr.agilium.ng.server.main.cristal.LDAP.password64=base64:YWdpbGl1bW5n
	 * fr.agilium.ng.server.main.cristal.LDAP.password64=basic:c2VjcmV0
	 * </pre>
	 *
	 * @param aValue
	 * @return
	 */
	private String decodeB64Value(final String aValue) {

		if (aValue == null) {
			return null;
		}
		String wValue = aValue;

		for (final String wPrefix : IBase64.PREFIXES) {
			//
			if (aValue.startsWith(wPrefix) || wPrefix.isEmpty()) {
				wValue = aValue.substring(wPrefix.length());
				if (!wValue.isEmpty()) {
					final CBase64Decoder wCBase64Decoder = new CBase64Decoder(
							wValue);
					try {
						wValue = new String(wCBase64Decoder.getBytes(),
								CXBytesUtils.ENCODING_UTF_8);
					} catch (final UnsupportedEncodingException e) {
						getLogger().logSevere(this, "decodeB64Value",
								"ERROR: %s", e);
						wValue = String.format("[B64 ERROR - %s - %s]", e
								.getClass().getSimpleName(), e.getMessage());
					}
					break;
				}
			}
		}
		return wValue;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#dumpProperties
	 * ()
	 */
	@Override
	public String dumpProperties() {

		final StringBuilder wSB = new StringBuilder();
		wSB.append(String.format("nbPropoerties=[%d]", size()));
		int wIdx = 0;
		for (final Entry<Object, Object> wProperty : getProperties().entrySet()) {
			wSB.append(String.format("\n(%2d)%40s=[%s]", wIdx, wProperty
					.getKey().toString(), wProperty.getValue().toString()));
			wIdx++;
		}
		return wSB.toString();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#getConfigBaseFile
	 * ()
	 */
	@Override
	public File getConfigBaseFile() {
		return new File(getConfigDir(), getConfigBaseFileName());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#
	 * getConfigBaseFileName()
	 */
	@Override
	public String getConfigBaseFileName() {
		return pConfigName + PROPERTIES_BASE_XML;
	}

	/**
	 * @return
	 */
	protected File getConfigBaseResourceFile() {
		return getFileFromResource(getConfigBaseResourcePath());
	}

	/**
	 * @return
	 */
	protected String getConfigBaseResourcePath() {
		return String.format("%s/%s", pResourcePath, getConfigBaseFileName());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#getConfigDir()
	 */
	@Override
	public File getConfigDir() {
		return pConfigDir;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#getConfigFile()
	 */
	@Override
	public File getConfigFile() {
		return new File(getConfigDir(), getConfigFileName());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#getConfigFileName
	 * ()
	 */
	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#getConfigFileName
	 * ()
	 */
	@Override
	public String getConfigFileName() {
		return pConfigName + PROPERTIES_XML;
	}

	/**
	 * @return
	 */
	protected File getConfigResourceFile() {
		return getFileFromResource(getConfigResourcePath());
	}

	/**
	 * @return
	 */
	protected String getConfigResourcePath() {
		return String.format("%s/%s", pResourcePath, getConfigFileName());
	}

	/**
	 * @param aResourcePath
	 * @return
	 */
	protected File getFileFromResource(final String aResourcePath) {
		return new File(pResourceLoader.getResource(aResourcePath)
				.getFile());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#getProperties()
	 */
	@Override
	public Properties getProperties() {
		return pProperties;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.isandlatech.x3.loadbalancer.ISvcWebAppListener#getWebAppProperty(
	 * java.lang.String)
	 */
	@Override
	public String getProperty(final String aPropertyName) {
		return getProperty(aPropertyName, null);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.isandlatech.x3.loadbalancer.ISvcWebAppListener#getWebAppProperty(
	 * java.lang.String, java.lang.String)
	 */
	@Override
	public String getProperty(final String aPropertyName, final String aDefault) {

		String wValue = pProperties.getProperty(aPropertyName);
		if (wValue == null) {
			getLogger().logDebug("getWebAppProperty",
					"Property [%s] doesn't exist. Default value=[%s]",
					aPropertyName, aDefault);
			wValue = aDefault;
		}
		return wValue;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#getPropertyArray
	 * (java.lang.String, java.lang.String)
	 */
	@Override
	public String[] getPropertyArray(final String aPropertyName,
			final String aSeparator) {

		return getPropertyArray(aPropertyName, aSeparator, null);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#getPropertyArray
	 * (java.lang.String, java.lang.String, java.lang.String[])
	 */
	@Override
	public String[] getPropertyArray(final String aPropertyName,
			final String aSeparator, final String[] aDefault) {

		final String wValue = pProperties.getProperty(aPropertyName);

		return wValue == null ? aDefault : wValue.split(aSeparator);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.isandlatech.webapp.utilities.ISvcWebApp#getWebAppPropertyBool(java
	 * .lang.String)
	 */
	@Override
	public String getPropertyB64(final String aPropertyName) {
		return getPropertyB64(aPropertyName, null);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#getPropertyB64
	 * (java.lang.String, java.lang.String)
	 */
	@Override
	public String getPropertyB64(final String aPropertyName,
			final String aDefault) {
		final String wValue = getProperty(aPropertyName, aDefault);

		return decodeB64Value(wValue);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.isandlatech.webapp.utilities.ISvcWebApp#getWebAppPropertyBool(java
	 * .lang.String)
	 */
	@Override
	public boolean getPropertyBool(final String aPropertyName) {
		return getPropertyBool(aPropertyName, null);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.isandlatech.webapp.utilities.ISvcWebApp#getWebAppPropertyBool(java
	 * .lang.String, java.lang.String)
	 */
	@Override
	public boolean getPropertyBool(final String aPropertyName,
			final String aDefault) {
		final String wValue = getProperty(aPropertyName, aDefault);

		return "true".equalsIgnoreCase(wValue)
				|| "yes".equalsIgnoreCase(wValue)
				|| "on".equalsIgnoreCase(wValue);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.isandlatech.x3.loadbalancer.ISvcWebAppListener#getWebAppPropertyInt
	 * (java.lang.String)
	 */
	@Override
	public int getPropertyInt(final String aPropertyName) {
		return getPropertyInt(aPropertyName, null);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.isandlatech.x3.loadbalancer.ISvcWebAppListener#getWebAppPropertyInt
	 * (java.lang.String, java.lang.String)
	 */
	@Override
	public int getPropertyInt(final String aPropertyName, final String aDefault) {

		final String wValue = getProperty(aPropertyName, aDefault);
		try {
			return Integer.parseInt(wValue);
		} catch (final Throwable e) {
			getLogger().logSevere("getWebAppPropertyInt",
					"Property [%s], unable to retrieve int value in [%s] %s",
					aPropertyName, wValue, e);
			return -1;
		}
	}

	/**
	 * @throws IOException
	 *
	 */
	private void init() throws IOException {

		
		final File wConfigBaseFile = getConfigBaseFile();
		
		// Delete BASE config file if it doesn't exist

		if (wConfigBaseFile.exists()) {
			boolean wDeleted =wConfigBaseFile.delete();
			getLogger()
			.logInfo(
					this,
					"init","Force delete BASE config file. deleted=[%s]",wDeleted);
		}
		
		// Create BASE config file if it doesn't exist
		if (!wConfigBaseFile.exists()) {
			getLogger().logInfo(this, "init",
					"MUST create BASE    config file from resource [%s]",
					getConfigBaseResourceFile());

			final Path wConfigBasePath = wConfigBaseFile.toPath();
			Files.copy(getConfigBaseResourceFile().toPath(), wConfigBasePath);
			getLogger()
					.logInfo(
							this,
							"init",
							"Create BASE    config file from resources( timestamp=[%s] size=[%s])",
							Files.getLastModifiedTime(wConfigBasePath),
							Files.size(wConfigBasePath));
		}

		// Create CURRENT config file if it doesn't exist
		final File wConfigFile = getConfigFile();
		if (!wConfigFile.exists()) {
			getLogger().logInfo(this, "init",
					"MUST create CURRENT config file from resource [%s]",
					getConfigResourceFile());
			final Path wConfigPath = wConfigFile.toPath();
			Files.copy(getConfigResourceFile().toPath(), wConfigPath);
			getLogger()
					.logInfo(
							this,
							"init",
							"Create CURRENT config file from resources( timestamp=[%s] size=[%s])",
							Files.getLastModifiedTime(wConfigPath),
							Files.size(wConfigPath));
		}

		// Load BASE config file
		final Properties wPropertiesBase = readPropertiesXmlFile(wConfigBaseFile);
		if (wPropertiesBase != null) {
			getLogger().logInfo(this, "init",
					"Read [%2d] properties from BASE    config file [%s]",
					wPropertiesBase.size(), wConfigBaseFile);
			pProperties.putAll(wPropertiesBase);
		}

		// Load CURRENT config file
		final Properties wProperties = readPropertiesXmlFile(getConfigFile());
		if (wProperties != null) {
			getLogger().logInfo(this, "init",
					"Read [%2d] properties from CURRENT config file [%s]",
					wProperties.size(), wConfigFile);

			pProperties.putAll(wProperties);
		}

	}

	/**
	 * @param aPropertiesXmlFile
	 * @return
	 */
	protected Properties readPropertiesXmlFile(File aPropertiesXmlFile) {

		if (aPropertiesXmlFile == null) {
			return null;
		}
		if (!aPropertiesXmlFile.exists() || !aPropertiesXmlFile.isFile()) {
			getLogger().logSevere(this, "readPropertiesXmlFile",
					"PropertiesXmlFile [%s] doesn't exist", aPropertiesXmlFile);
			return null;
		}
		if (!aPropertiesXmlFile.isFile()) {
			getLogger().logSevere(this, "readPropertiesXmlFile",
					"PropertiesXmlFile [%s] isn't a file", aPropertiesXmlFile);
			return null;
		}
		try {
			java.io.BufferedInputStream bin = null;
			final FileInputStream in = new FileInputStream(aPropertiesXmlFile);
			final Properties wProperties = new java.util.Properties();
			bin = new java.io.BufferedInputStream(in);
			wProperties.loadFromXML(bin);
			in.close();
			return wProperties;
		} catch (final Exception e) {
			getLogger().logSevere(this, "readPropertiesXmlFile", "ERROR %s", e);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.cohorte.utilities.picosoc.webapp.ISvcWebAppProperties#size()
	 */
	@Override
	public int size() {
		return pProperties.size();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return addDescriptionInSB(new StringBuilder(128)).toString();
	}

}
