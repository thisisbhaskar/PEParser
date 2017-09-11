#include "PEParser.h"
#include "PEParserImpl.h"

using namespace PEParser;

list<PEHANDLE> PEParser::g_PEHandleList;

namespace PEParser {

	PEHANDLE OpenFile(wstring const & p_PEFilePath) {

		HANDLE l_fileHandle = CreateFile(p_PEFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == l_fileHandle) {
			return NULL;
		}

		PEInfo * l_PEInfo = new PEInfo(l_fileHandle);
		g_PEHandleList.push_back((PEHANDLE)l_PEInfo);
		return (PEHANDLE)l_PEInfo;
	}

	void CloseFile(PEHANDLE p_PEHandle) {

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

		try {
			getDOSHeader(); /* Get DOS Header */
			getNTHeader();  /* Get NT Header (including Optinal Header) */
			m_cachedData.insert(CachedData::PE_HEADER_INFO); /* Mark cached */
		}
		catch (PEParser::PEParserException const & l_exception) {
			m_PEHeaderInfo->reset(); /* Reset Cache  */
			throw l_exception;
		}

	}

	void PEInfo::getDOSHeader() {

		/* Initialize header information */
		IMAGE_DOS_HEADER l_dos_header;
		DWORD l_bytes_read;
		bool l_successful = ReadFile(m_PEFileHandle, &l_dos_header, sizeof(IMAGE_DOS_HEADER), &l_bytes_read, NULL);
		if (!l_successful) {
			/* Failed to read data */
			throw PEParser::PEParserException(L"Failed to read data.");
		}

		if (0 == l_bytes_read) {
			m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
			return;
		}

		if (sizeof(IMAGE_DOS_HEADER) != l_bytes_read) {
			m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
			return;
		}

		if (IMAGE_DOS_SIGNATURE != l_dos_header.e_magic) {
			m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
			return;
		}

		/* Set DOS Header */
		m_PEHeaderInfo->setDOSHeader(l_dos_header); 
		m_PEHeaderInfo->hasDOSHeader(true);

	}

	void PEInfo::getNTHeader() {

		bool l_hasDOSHeader = m_PEHeaderInfo->hasDOSHeader();
		if (!l_hasDOSHeader) {
			return; /* No DOS Header */
		}

		/* Seek to File Header position */
		IMAGE_DOS_HEADER l_dos_header = m_PEHeaderInfo->getDOSHeader();
		LONG l_elf_position = l_dos_header.e_lfanew;
		DWORD l_move_return = SetFilePointer(m_PEFileHandle, l_elf_position, NULL, FILE_BEGIN);
		if (INVALID_SET_FILE_POINTER == l_move_return) {
			m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
			return;
		}

		/* Attempt to read File Header */
		IMAGE_NT_HEADERS32 l_image_file_header;
		DWORD l_bytes_read;
		bool l_successful = ReadFile(m_PEFileHandle, &l_image_file_header, sizeof(IMAGE_NT_HEADERS32), &l_bytes_read, NULL);
		if (!l_successful) {
			throw PEParser::PEParserException(L"Failed to read data.");
		}

		if (0 == l_bytes_read) {
			m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
			return;
		}

		if (IMAGE_NT_SIGNATURE != l_image_file_header.Signature) {
			m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
			return;
		} 

		m_PEHeaderInfo->setFileHeader(l_image_file_header.FileHeader); /* Set File Header */
		m_PEHeaderInfo->hasNTHeader(true);

		/* Get Image Type */
		WORD l_characterstics = l_image_file_header.FileHeader.Characteristics;
		if (!(IMAGE_FILE_EXECUTABLE_IMAGE & l_characterstics)) {
			/* We don't support currently */
			m_PEHeaderInfo->setPEFileType(PEFileType::NOT_SUPPORTED);
		}

		if (IMAGE_FILE_DLL & l_characterstics) {
			m_PEHeaderInfo->setPEFileType(PEFileType::DLL_FILE);
		}
		else if (IMAGE_FILE_SYSTEM & l_characterstics) {
			m_PEHeaderInfo->setPEFileType(PEFileType::SYS_FILE);
		}
		else {
			/* TODO: EXE ???? */
			m_PEHeaderInfo->setPEFileType(PEFileType::EXE_FILE);
		}

		/* Get BITNess (32 or 64) */
		WORD l_opt_header_magic = l_image_file_header.OptionalHeader.Magic;
		if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == l_opt_header_magic) {
			m_PEHeaderInfo->setBITNess(BITNess::BITNESS_32);
			m_PEHeaderInfo->setOptHeader32(l_image_file_header.OptionalHeader);
		}
		else if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == l_opt_header_magic) {

			m_PEHeaderInfo->setBITNess(BITNess::BITNESS_64);

			DWORD l_move_return = SetFilePointer(m_PEFileHandle, l_elf_position, NULL, FILE_BEGIN);
			if (INVALID_SET_FILE_POINTER == l_move_return) {
				m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
				return;
			}

			/* Get 64 BIT header */
			IMAGE_NT_HEADERS64 l_image_file_header;
			DWORD l_bytes_read;
			bool l_successful = ReadFile(m_PEFileHandle, &l_image_file_header, sizeof(IMAGE_NT_HEADERS64), &l_bytes_read, NULL);
			if (!l_successful) {
				throw PEParser::PEParserException(L"Failed to read data.");
			}

			if (0 == l_bytes_read) {
				m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
				return;
			}
			else {
				m_PEHeaderInfo->setOptHeader64(l_image_file_header.OptionalHeader);
			}
		}
	}

	PEHeaderInfo::PEHeaderInfo() {

		m_hasDosHeader = false;
		m_hasNTHeader = false;
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

		m_hasDosHeader = false;
		m_hasNTHeader = false;
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