package org.psem2m.utilities.logging;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.FileHandler;

import org.psem2m.utilities.CXException;
import org.psem2m.utilities.CXOSUtils;
import org.psem2m.utilities.CXStringUtils;
import org.psem2m.utilities.IXDescriber;
import org.psem2m.utilities.files.CXFileText;

/**
 * @author ogattaz
 * 
 */
public class CActivityFileHandler extends FileHandler implements IXDescriber {

	public final static String LABEL_COUNT = "Count";

	public final static String LABEL_EXISTING = "ExistingFileNames";

	public final static String LABEL_PATTERN = "Pattern";

	private final static int LIMIT_STD = 1000000 * 5;

	private final static String MESS_NOT_A_VARID = "The pattern variable [%s] is unknown.";

	private final static String MESS_PARENT_DOESNT_EXIST = "The parent directory [%s] does'nt exist.";

	private final static String MESS_UNABLE_FIND_VARID = "Unable to get pattern var id at the index [%d].The pattern size is [%d].";

	private final static String VAR_G = "%g";

	private final static String VAR_H = "%h";

	private final static String VAR_PREFIX = "%";

	private final static String VAR_T = "%t";

	private final int pCount;

	private final CXFileText[] pFiles;

	private final String pPattern;

	/**
	 * @param aPattern
	 * @param aCount
	 * @throws Exception
	 */
	CActivityFileHandler(final String aPattern, final int aCount) throws Exception {

		this(aPattern, LIMIT_STD, aCount);
	}

	/**
	 * @param aPattern
	 * @param aLimit
	 * @param aCount
	 * @throws Exception
	 */
	public CActivityFileHandler(final String aPattern, final int aLimit, final int aCount)
			throws Exception {

		this(aPattern, aLimit, aCount, true);
	}

	/**
	 * @param aPattern
	 * @param aLimit
	 * @param aCount
	 */
	CActivityFileHandler(final String aPattern, final int aLimit, final int aCount,
			final boolean append) throws Exception {

		super(aPattern, aLimit, aCount, append);
		setEncoding(CXOSUtils.ENCODING_UTF_8);
		pPattern = aPattern;
		pCount = aCount;
		pFiles = new CXFileText[pCount];
		intFiles();
	}

	@Override
	public Appendable addDescriptionInBuffer(final Appendable aBuffer) {

		CXStringUtils.appendKeyValInBuff(aBuffer, LABEL_PATTERN, getPattern());
		CXStringUtils.appendKeyValInBuff(aBuffer, LABEL_COUNT, getCount());
		CXStringUtils.appendKeyValInBuff(aBuffer, LABEL_EXISTING, dumpExistingFileNames());
		return aBuffer;
	}

	private StringBuilder addExistingFileNamesInSB(final StringBuilder aSB) {

		List<String> wFileNames = getExistingFileNames();
		Iterator<String> wFileNamesIt = wFileNames.iterator();
		while (wFileNamesIt.hasNext()) {
			if (aSB.length() > 0) {
				aSB.append(',');
			}
			aSB.append(wFileNamesIt.next());
		}
		return aSB;
	}

	public int calcDescriptionLength() {

		return 256;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.util.logging.FileHandler#close()
	 */
	@Override
	public void close() throws SecurityException {

		if (CXOSUtils.isOsMacOsX()) {

			Thread wClosingThread = new Thread(new Runnable() {
				@Override
				public void run() {

					try {
						CActivityFileHandler.super.close();
					} catch (Exception e) {
						System.err.println(CXException.eInString(e));
					}
				}
			}, "Closing log thread");
			// Allows the Java Virtual Machine to exit even this Thread is
			// running
			wClosingThread.setDaemon(true);

			wClosingThread.start();

		} else {
			super.close();
		}
	}

	/**
	 * @return
	 */
	private String dumpExistingFileNames() {

		return addExistingFileNamesInSB(new StringBuilder(32 * getCount())).toString();
	}

	/**
	 * @param generation
	 * @param unique
	 * @return
	 * @throws IOException
	 */
	private CXFileText generate(final int aGenerationNum) throws Exception {

		String wPath = replacePatternVariables(getPattern(), aGenerationNum);

		CXFileText wFile = new CXFileText(wPath);
		if (!wFile.getParentFile().exists()) {
			String wMess = String.format(MESS_PARENT_DOESNT_EXIST, wFile.getParent());
			throw new IOException(wMess);
		}

		return wFile;
	}

	/**
	 * @return
	 */
	int getCount() {

		return pCount;
	}

	/**
	 * @return
	 */
	public List<String> getExistingFileNames() {

		ArrayList<String> wFileNames = new ArrayList<String>();
		Iterator<CActivityFileText> wFilesIt = getExistingFiles().iterator();
		while (wFilesIt.hasNext()) {
			wFileNames.add(wFilesIt.next().getName());
		}
		return wFileNames;
	}

	/**
	 * @return
	 */
	public List<CActivityFileText> getExistingFiles() {

		ArrayList<CActivityFileText> wFiles = new ArrayList<CActivityFileText>();
		int wI = 0;
		while (wI < pCount) {
			if (pFiles[wI].exists()) {
				wFiles.add(new CActivityFileText(pFiles[wI]));
			}
			wI++;
		}
		return wFiles;
	}

	/**
	 * @return
	 */
	String getPattern() {

		return pPattern;
	}

	/**
   * 
   */
	private void intFiles() throws Exception {

		int wI = 0;
		while (wI < pCount) {
			pFiles[wI] = generate(wI);
			wI++;
		}
	}

	/**
	 * @param aPatternVariableId
	 * @param aPattern
	 * @return
	 * @throws Exception
	 */
	private String replacePatternVariable(final String aPattern, final int aGenerationNum,
			final String aPatternVariableId) throws Exception {

		String wValue = null;
		if (VAR_T.equals(aPatternVariableId)) {
			wValue = System.getProperty("java.io.tmpdir");
			if (wValue == null) {
				wValue = System.getProperty("user.home");
			}
		} else if (VAR_H.equals(aPatternVariableId)) {
			wValue = System.getProperty("user.home");
		} else if (VAR_G.equals(aPatternVariableId)) {
			wValue = String.valueOf(aGenerationNum);
		} else {
			String wMess = String.format(MESS_NOT_A_VARID, aPatternVariableId);
			throw new Exception(wMess);
		}
		return aPattern.replace(aPatternVariableId, wValue);
	}

	/**
	 * <ul>
	 * <li>/ separateur de repertoires dans le systeme de fichier local
	 * <li>%g le nombre genere automatiquement par la rotation cyclique des
	 * fichiers
	 * <li>%t repertoire temporaire du systeme
	 * <li>%h repertoire de connexion de l'utilisateur (equivalent de
	 * "user.home" )
	 * <li>%u un nombre aleatoire unique <b>==> non supporte !</b>
	 * <ul>
	 * Pour despecialiser le caractere '%', il faut le doubler.
	 * 
	 * Exemple : "%t/myApps.%g.log", 10000, 4
	 * 
	 * @param tring
	 * @return
	 */
	private String replacePatternVariables(String aPattern, final int aGenerationNum)
			throws Exception {

		int wPercentPos = aPattern.indexOf(VAR_PREFIX);
		String wVariableId;
		while (wPercentPos > -1) {
			if (wPercentPos + 1 > aPattern.length() - 1) {
				String wMess = String.format(MESS_UNABLE_FIND_VARID, wPercentPos + 1,
						aPattern.length());
				throw new Exception(wMess);
			}
			wVariableId = VAR_PREFIX + aPattern.charAt(wPercentPos + 1);
			aPattern = replacePatternVariable(aPattern, aGenerationNum, wVariableId);
			wPercentPos = aPattern.indexOf(VAR_PREFIX);
		}

		return aPattern;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.psem2m.utilities.IXDescriber#toDescription()
	 */
	@Override
	public String toDescription() {

		return addDescriptionInBuffer(new StringBuilder(calcDescriptionLength())).toString();
	}
}
