#include "PEParser.h"
#include "PEParserImpl.h"

using namespace PEParser;

list<PEHANDLE> PEParser::g_PEHandleList;

namespace PEParser {

	PEHANDLE OpenPEFile(wstring const & p_PEFilePath) {

		HANDLE l_fileHandle = CreateFile(p_PEFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == l_fileHandle) {
			return NULL;
		}

		PEInfo * l_PEInfo = new PEInfo(l_fileHandle);
		g_PEHandleList.push_back((PEHANDLE)l_PEInfo);
		return (PEHANDLE)l_PEInfo;
	}

	void FreePEFile(PEHANDLE p_PEHandle) {

		if (NULL != p_PEHandle) {
			delete (PEInfo*)(p_PEHandle);
		}
	}

	PEFileType getPEFileType(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getPEFileType();
	}

	BITNess PEParser::getBITNess(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getBITNess();
	}

	IMAGE_DOS_HEADER PEParser::getDOSHeader(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getDOSHeader();
	}

	IMAGE_FILE_HEADER PEParser::getFileHeader(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getFileHeader();
	}

	IMAGE_OPTIONAL_HEADER64 PEParser::getOptHeader64(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getOptHeader64();
	}

	IMAGE_OPTIONAL_HEADER32 PEParser::getOptHeader32(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getOptHeader32();
	}

	PEInfo::PEInfo(HANDLE const & p_fileHandle) : m_PEFileHandle(p_fileHandle) {
		m_PEHeaderInfo = new PEHeaderInfo();
	}

	PEInfo::~PEInfo() {
		delete m_PEHeaderInfo;
		CloseHandle(m_PEFileHandle);
	}

	void PEInfo::readHeaderData() {

		if (m_cachedData.count(CachedData::PE_HEADER_INFO) < 0) {
			return;
		}

		/* Initialize header information */
		IMAGE_DOS_HEADER l_dos_header;
		DWORD l_bytes_read;
		bool l_successful = ReadFile(m_PEFileHandle, &l_dos_header, sizeof(IMAGE_DOS_HEADER), &l_bytes_read, NULL);
		if (l_successful) {
			if (0 == l_bytes_read) {
				m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
			}
			else {
				if (sizeof(IMAGE_DOS_HEADER) == l_bytes_read) {
					if (IMAGE_DOS_SIGNATURE == l_dos_header.e_magic) {
						m_PEHeaderInfo->setDOSHeader(l_dos_header);
						m_PEHeaderInfo->setPEFileType(PEFileType::NOT_SUPPORTED);
					}
					else {
						m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
					}
				}
				else {
					m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
				}
			}
		}
		else {
			/* Failed to read data */
			throw PEParser::PEParserException(L"Failed to read data.");
		}


		m_cachedData.insert(CachedData::PE_HEADER_INFO); /* Mark cached */
	}

	PEHeaderInfo::PEHeaderInfo() {

		m_PEFileType = PEFileType::NOT_SUPPORTED;
		m_BITNess = BITNess::BITNESS_UNKNOWN;
		m_dosHeader = NULL;
		m_fileHeader = NULL;
		m_optionalHeader64 = NULL;
		m_optionalHeader64 = NULL;
	}

	PEHeaderInfo::~PEHeaderInfo() {
		reset();
	}

	void PEHeaderInfo::reset() {

		m_PEFileType = PEFileType::NOT_SUPPORTED;
		m_BITNess = BITNess::BITNESS_UNKNOWN;

		if (NULL != m_dosHeader) {
			delete m_dosHeader;
			m_dosHeader = NULL;
		}

		if (NULL != m_fileHeader) {
			delete m_fileHeader;
			m_fileHeader = NULL;
		}

		if (NULL != m_optionalHeader64) {
			delete m_optionalHeader64;
			m_optionalHeader64 = NULL;
		}

		if (NULL != m_optionalHeader32) {
			delete m_optionalHeader32;
			m_optionalHeader32 = NULL;
		}
	}
}