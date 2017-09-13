#include "PEParser.h"
#include "PEParserImpl.h"

using namespace PEParser;

list<PEHANDLE> PEParser::g_PEHandleList;

namespace PEParser {

	/**
	* Open file resouce handle
	*/
	PEHANDLE OpenFile(wstring const & p_PEFilePath) {

		HANDLE l_fileHandle = CreateFile(p_PEFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == l_fileHandle) {
			return NULL;
		}

		PEInfo * l_PEInfo = new PEInfo(l_fileHandle);
		g_PEHandleList.push_back((PEHANDLE)l_PEInfo);
		return (PEHANDLE)l_PEInfo;
	}

	/**
	* Close file resouce handle
	*/
	void CloseFile(PEHANDLE p_PEHandle) {

		if (NULL != p_PEHandle) {
			delete (PEInfo*)(p_PEHandle);
		}
	}

	/**
	* Get file type
	*/
	PEFileType getFileType(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getFileType();
	}

	/**
	* Bet BIT ness. Valid only if the file is a valid binary
	*/
	BITNess getBITNess(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getBITNess();
	}

	/**
	* Get Does header. Valid only if the file is a valid binary
	*/
	IMAGE_DOS_HEADER getDOSHeader(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getDOSHeader();
	}

	/**
	* Get File header. Valid only if the file is a valid binary
	*/
	IMAGE_FILE_HEADER getFileHeader(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getFileHeader();
	}

	/**
	* Get 64bit optinal header. Valid only if the file is 64bit binary
	*/
	IMAGE_OPTIONAL_HEADER64 getOptHeader64(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getOptHeader64();
	}

	/**
	* Get 32bit optinal header. Valid only if the file is 32bit binary
	*/
	IMAGE_OPTIONAL_HEADER32 getOptHeader32(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getOptHeader32();
	}

	/**
	* Get number of section headers. Valid only if the file is a valid binary
	*/
	size_t getNoOfSectionHeaders(PEHANDLE p_PEHandle) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		return l_PEInfo->m_PEHeaderInfo->getNoOfSections();
	}

	/**
	* Copies section headers to the given buffer. Valid only if the file is a valid binary
	*/
	bool getSectionHeaders(PEHANDLE p_PEHandle, IMAGE_SECTION_HEADER* p_buffer, size_t p_size_of_buffer) {

		PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
		l_PEInfo->readHeaderData();

		size_t l_req_size = getNoOfSectionHeaders(p_PEHandle) * sizeof(IMAGE_SECTION_HEADER);
		if (p_size_of_buffer < l_req_size) {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return false;
		}
		else {
			memcpy_s(p_buffer, p_size_of_buffer, l_PEInfo->m_PEHeaderInfo->m_sectionHeaderStart, l_req_size);
			return true;
		}
	}
}