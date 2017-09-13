#include "PEParserImpl.h"

using namespace PEParser;

/**
* PEInfo constructor. Takes handles to the file as input
*/
PEInfo::PEInfo(HANDLE const & p_fileHandle) : m_PEFileHandle(p_fileHandle) {
	m_PEHeaderInfo = new PEHeaderInfo();
}

/**
* Destructor
*/
PEInfo::~PEInfo() {
	delete m_PEHeaderInfo;
	CloseHandle(m_PEFileHandle);
}

/**
* Read header data of the PE file.
*/
void PEInfo::readHeaderData() {

	if (m_cachedData.count(CachedData::PE_HEADER_INFO) < 0) {
		/* We already have PE header information. Nothign to do */
		return;
	}

	m_PEHeaderInfo->reset(); /* Reset Cache */

	try {
		getDOSHeader(); /* Get DOS Header */
		getNTHeader();  /* Get NT Header (including Optinal Header) */
		getSectionHeaders(); /* Get Section Headers */
		m_cachedData.insert(CachedData::PE_HEADER_INFO); /* Mark cached */
	}
	catch (PEParser::PEParserException const & l_exception) {
		m_PEHeaderInfo->reset(); /* Reset Cache  */
		throw l_exception;
	}

}

/**
* Read DOS header
*/
void PEInfo::getDOSHeader() {

	/* Initialize header information */
	IMAGE_DOS_HEADER l_dos_header;
	DWORD l_bytes_read;
	bool l_successful = ReadFile(m_PEFileHandle, &l_dos_header, sizeof(IMAGE_DOS_HEADER), &l_bytes_read, NULL);
	if (!l_successful) {
		/* Failed to read data */
		throw PEParser::PEParserException(L"Failed to read data.");
	}

	if (0 == l_bytes_read || sizeof(IMAGE_DOS_HEADER) != l_bytes_read) {
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

/**
* Read NT headers
* TODO: This is not correct. We are blindly redaing data sections (16)
*/
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
		m_PEHeaderInfo->setPEFileType(PEFileType::NOT_SUPPORTED);
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

/**
* Read PE section headers and store them on heap.
* Heap is required as we don't the numer of section in advance.
*/
void PEInfo::getSectionHeaders() {

	PEFileType l_pe_file_type = m_PEHeaderInfo->getFileType();
	if (PEFileType::NOT_A_PE_FILE == l_pe_file_type
		|| PEFileType::NOT_SUPPORTED == l_pe_file_type) {
		return; /* We cannot do much  */
	}

	size_t l_section_header_offset =
		m_PEHeaderInfo->m_dosHeader.e_lfanew +				/* Start of NT Header */
		sizeof(DWORD) +										/* NT Signature */
		sizeof(IMAGE_FILE_HEADER) +							/* File Header */
		m_PEHeaderInfo->m_fileHeader.SizeOfOptionalHeader;	/* Size of optional header */

															/* Seek to File Header position */
	DWORD l_move_return = SetFilePointer(m_PEFileHandle, l_section_header_offset, NULL, FILE_BEGIN);
	if (INVALID_SET_FILE_POINTER == l_move_return) {
		m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
		return;
	}

	WORD l_no_of_sections = m_PEHeaderInfo->m_fileHeader.NumberOfSections;
	DWORD l_size_of_section_headers = l_no_of_sections * sizeof(IMAGE_SECTION_HEADER);

	/* Read section headers */
	IMAGE_SECTION_HEADER* l_section_headers = (IMAGE_SECTION_HEADER*)malloc(l_size_of_section_headers);
	DWORD l_bytes_read;
	bool l_successful = ReadFile(m_PEFileHandle, l_section_headers, l_size_of_section_headers, &l_bytes_read, NULL);
	if (!l_successful) {
		free(l_section_headers);
		throw PEParser::PEParserException(L"Failed to read data.");
	}

	if (0 == l_bytes_read || l_size_of_section_headers != l_bytes_read) {
		m_PEHeaderInfo->setPEFileType(PEFileType::NOT_A_PE_FILE);
		free(l_section_headers);
		return;
	}
	else {
		m_PEHeaderInfo->m_noOfSections = l_no_of_sections;
		m_PEHeaderInfo->m_sectionHeaderStart = l_section_headers;
	}

	/* Just to debug the data, iterate on each of the section header */
	for (int l_counter = 0; l_counter < l_no_of_sections; l_counter++) {
		IMAGE_SECTION_HEADER* l_sectionHeader = l_section_headers + l_counter;
		string l_sectionName = string((char*)l_sectionHeader->Name);
	}
}

/**
* Constructor
*/
PEHeaderInfo::PEHeaderInfo() {

	m_hasDosHeader = false;
	m_hasNTHeader = false;
	m_PEFileType = PEFileType::NOT_SUPPORTED;
	m_BITNess = BITNess::BITNESS_UNKNOWN;
	m_noOfSections = 0;
	m_sectionHeaderStart = NULL;
}

/**
* Destructor
*/
PEHeaderInfo::~PEHeaderInfo() {
	reset();
}
/**
* Reset the PE header data.
*/
void PEHeaderInfo::reset() {

	m_hasDosHeader = false;
	m_hasNTHeader = false;
	m_PEFileType = PEFileType::NOT_SUPPORTED;
	m_BITNess = BITNess::BITNESS_UNKNOWN;
	m_noOfSections = 0;

	if (m_sectionHeaderStart) {
		free(m_sectionHeaderStart);
		m_sectionHeaderStart = NULL;
	}
}