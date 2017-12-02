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
    * Allocates buffer for section headers and returns the data in the 
    * buffer allocated. Caller must free the buffer with free call once 
    * client is done with using the buffer.
    * Also copies number of sections in the p_no_of_sections parameter
    */
    IMAGE_SECTION_HEADER* getSectionHeaders(PEHANDLE p_PEHandle, size_t & p_no_of_sections) {

        PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
        l_PEInfo->readHeaderData();

        p_no_of_sections = getNoOfSectionHeaders(p_PEHandle);
        size_t l_req_size = p_no_of_sections * sizeof(IMAGE_SECTION_HEADER);
        IMAGE_SECTION_HEADER* l_buffer = (IMAGE_SECTION_HEADER*) malloc(l_req_size);
        memcpy_s(l_buffer, l_req_size, l_PEInfo->m_PEHeaderInfo->m_sectionHeaderStart, l_req_size);

        return l_buffer;
    }
}