package org.cohorte.utilities.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.psem2m.utilities.CXBytesUtils;
import org.psem2m.utilities.CXTimer;
import org.psem2m.utilities.logging.CActivityLoggerNull;
import org.psem2m.utilities.logging.IActivityLogger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Generates Certificate, KeyPair or RsaKeyContext
 *
 * @author ogattaz
 *
 */
public class CRsaGenerator {

	/** String to hold name of the encryption algorithm. */
	public static final String ALGORITHM_GENERATE = "RSA";
	public static final int ALGORITHM_GENERATE_SIZE = 1024;

	/** String to hold name of the encryption algorithm. */
	public static final String ALGORITHM_SIGN = "SHA1withRSA";

	public static final String DISTINGUISEDNAME = "CN=isandlaTech,L=Grenoble,C=FR";

	/** certificate duration */
	public static int NB_DAYS_IN_YEAR = 365;
	
	/**
	 * Add Bouncy Castle security provider, once and for all.
	 */
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/** Nb milliseconds in a day */
	public static final long NB_MILLI_IN_DAY = 86400000l;

	public final KeyPairGenerator keyGen;

	private final String pDistinguishedName;

	private final int pKeySize;

	private final IActivityLogger pLogger;

	/**
	 * @param aLogger
	 * @param aDistinguishedName
	 * @throws NoSuchAlgorithmException
	 */
	public CRsaGenerator(final IActivityLogger aLogger,
			final String aDistinguishedName) throws NoSuchAlgorithmException {

		this(aLogger, aDistinguishedName, ALGORITHM_GENERATE_SIZE);
	}

	/**
	 * MOD_OG_20150717 new signature accepting a key size
	 *
	 * @param aLogger
	 * @param aDistinguishedName
	 * @param aKeySize
	 * @throws NoSuchAlgorithmException
	 */
	public CRsaGenerator(final IActivityLogger aLogger,
			final String aDistinguishedName, final int aKeySize)
			throws NoSuchAlgorithmException {

		super();
		pLogger = (aLogger != null) ? aLogger : CActivityLoggerNull
				.getInstance();

		pDistinguishedName = (aDistinguishedName != null && !aDistinguishedName
				.isEmpty()) ? aDistinguishedName : DISTINGUISEDNAME;

		pKeySize = (aKeySize == 1024 || aKeySize == 2048) ? aKeySize
				: ALGORITHM_GENERATE_SIZE;

		keyGen = KeyPairGenerator.getInstance(ALGORITHM_GENERATE);
		keyGen.initialize(pKeySize);

		if (pLogger.isLogDebugOn()) {
			pLogger.logDebug(this, "<init>", "keyGen=[%s] Algo=[%s] Size=[%s]",
					keyGen, ALGORITHM_GENERATE, ALGORITHM_GENERATE_SIZE);
		}
	}

	/**
	 * @param aDistinguishedName
	 * @throws NoSuchAlgorithmException
	 */
	public CRsaGenerator(final String aDistinguishedName)
			throws NoSuchAlgorithmException {
		this(CActivityLoggerNull.getInstance(), aDistinguishedName);
	}

	/**
	 * @return a X509 certificate containing a new RSA keypair for "CN=Sage"
	 *
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public X509Certificate generateCertificate()
			throws GeneralSecurityException, IOException,
			NoSuchAlgorithmException {

		return generateCertificate(getDistinguishedName(), generateKeyPair(),
				NB_DAYS_IN_YEAR, getX509SignAlgorithm());
	}

	/**
	 * @param aDistinguishedName
	 *            the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
	 * @param aNbDays
	 *            how many days from now the Certificate is valid for
	 * @return
	 *
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public X509Certificate generateCertificate(String aDistinguishedName,
			int aNbDays) throws GeneralSecurityException, IOException,
			NoSuchAlgorithmException {

		return generateCertificate(aDistinguishedName, generateKeyPair(),
				aNbDays, getX509SignAlgorithm());
	}

	/**
	 * Create a self-signed X.509 Certificate
	 *
	 * @param aDistinguishedName
	 *            the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
	 * @param aKeyPair
	 *            the KeyPair
	 * @param aNbDays
	 *            how many days from now the Certificate is valid for
	 * @param aX509SignAlgorithm
	 *            the signing algorithm, eg "SHA1withRSA"
	 * @see
	 * "http://www.bouncycastle.org/wiki/display/JA1/BC+Version+2+APIs"
	 */
	public X509Certificate generateCertificate(String aDistinguishedName,
			KeyPair aKeyPair, int aNbDays, String aX509SignAlgorithm)
			throws GeneralSecurityException, IOException {

		if (pLogger.isLogDebugOn()) {
			pLogger.logDebug(
					this,
					"generateCertificate",
					"DistinguishedName=[%s] NbDays=[%s] Algorithm=[%s] KeyPair=[%s]",
					aDistinguishedName, aNbDays, aX509SignAlgorithm, aKeyPair);
		}

		final PrivateKey privkey = aKeyPair.getPrivate();
		final PublicKey publkey = aKeyPair.getPublic();

		ContentSigner sigGen;
		try {
			sigGen = new JcaContentSignerBuilder(ALGORITHM_SIGN)
				.setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.build(privkey);
		} catch (OperatorCreationException e) {
			pLogger.logSevere(
					this,
					"generateCertificate",
					"OperatorCreationException:\n [%s]",
					e);
			/**
			 * Not to change method signature for backward compatibility.
			 * Throw unchecked exception.
			 */
			throw new RuntimeException(e);
		}

		final Date from = new Date();
		final Date to = new Date(from.getTime() + aNbDays * NB_MILLI_IN_DAY);
		final BigInteger wSerialNumber = new BigInteger(64, new SecureRandom());
		final X500Name aOwner = new X500Name(aDistinguishedName);

		X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(
				aOwner,
				wSerialNumber,
				from, to,
				aOwner,
				publkey);
		
		X509CertificateHolder certHolder = v1CertGen.build(sigGen); 
		
		return new JcaX509CertificateConverter().setProvider( "BC" )
				  .getCertificate(certHolder);
	}

	/**
	 * @return
	 */
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {

		final CXTimer wTimer = CXTimer.newStartedTimer();

		final KeyPair wKeyPair = keyGen.generateKeyPair();
		wTimer.stop();
		if (pLogger.isLogDebugOn()) {
			pLogger.logDebug(this, "generateKeyPair",
					"Duration=[%s] Format=[%s] Public=[%s]", wTimer
							.getDurationStrMilliSec(), wKeyPair.getPublic()
							.getFormat(), CXBytesUtils
							.bytesToHexaString(wKeyPair.getPublic()
									.getEncoded()));
		}
		return wKeyPair;
	}

	/**
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 * @throws NoSuchAlgorithmException
	 */
	public CRsaKeyContext generateRsaKeyContext()
			throws NoSuchAlgorithmException, GeneralSecurityException,
			IOException {

		final CXTimer wKeyTimer = CXTimer.newStartedTimer();
		final KeyPair wKeyPair = keyGen.generateKeyPair();
		wKeyTimer.stop();

		final CXTimer wCertificatTimer = CXTimer.newStartedTimer();
		final X509Certificate wX509Certificate = generateCertificate(
				DISTINGUISEDNAME, wKeyPair, NB_DAYS_IN_YEAR, ALGORITHM_SIGN);
		wCertificatTimer.stop();

		// creates the context
		final CRsaKeyContext wCRsaKeyContext = new CRsaKeyContext(wKeyPair,
				wKeyTimer, wX509Certificate, wCertificatTimer);

		if (pLogger.isLogDebugOn()) {
			pLogger.logDebug(this, "generateRsaKeyContext",
					"OK RsaKeyContext.TimeStamp=[%s]",
					wCRsaKeyContext.getTimeStampIso8601());
		}
		return wCRsaKeyContext;
	}

	/**
	 * @return
	 */
	public String getAlgorithm() throws NoSuchAlgorithmException {

		return keyGen.getAlgorithm();
	}

	/**
	 * @return
	 */
	public String getDistinguishedName() {
		return pDistinguishedName;
	}

	/**
	 * @return
	 */
	public int getKeySize() {
		return pKeySize;
	}

	/**
	 * @return
	 */
	public String getX509SignAlgorithm() {
		return ALGORITHM_SIGN;
	}

}
