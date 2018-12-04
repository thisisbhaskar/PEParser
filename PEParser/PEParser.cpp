#include "PEParser.h"
#include "PEParserImpl.h"

using namespace PEParser;

list<PEHANDLE> PEParser::g_PEHandleList;

namespace PEParser
{

    /**
    * Open file resouce handle
    */
    PEHANDLE OpenFile(wstring const & p_PEFilePath)
    {
        bool l_continue = true;

        /* File Handle */
        HANDLE l_file_handle = NULL;
        l_file_handle = CreateFile(p_PEFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE == l_file_handle)
        {
            l_continue = false;
            l_file_handle = NULL;
        }

        /* File Mapping Handle */
        HANDLE l_filemappng_handle = NULL;
        if (l_continue)
        {
            l_filemappng_handle = CreateFileMapping(l_file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
            if (NULL == l_filemappng_handle)
            {
                l_continue = false;
            }
        }

        /* File View Pointer */
        PVOID l_view_ptr = NULL;
        if (l_continue)
        {
            l_view_ptr = MapViewOfFile(l_filemappng_handle, FILE_MAP_READ, 0, 0, 0);
            if (NULL == l_view_ptr)
            {
                l_continue = false;
            }
        }
        
        if (l_continue)
        {
            PEInfo * l_pe_info = new PEInfo(l_file_handle,
                                            l_filemappng_handle,
                                            l_view_ptr);
            g_PEHandleList.push_back((PEHANDLE)l_pe_info);
            return (PEHANDLE)l_pe_info;
        }
        else
        {
            /* Clear temp data */
            if (l_file_handle)
            {
                CloseHandle(l_file_handle);
            }

            if (l_filemappng_handle)
            {
                CloseHandle(l_filemappng_handle);
            }

            if (l_view_ptr)
            {
                UnmapViewOfFile(l_view_ptr);
            }
        }
        return NULL;
    }

    /**
    * Close file resouce handle
    */
    void CloseFile(PEHANDLE p_PEHandle)
    {
        if (NULL != p_PEHandle)
        {
            delete (PEInfo*)(p_PEHandle);
        }
    }

    /**
    * Get file type
    */
    PEFileType getFileType(PEHANDLE p_PEHandle)
    {
        PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
        l_PEInfo->readHeaderData();

        return l_PEInfo->m_pe_headers_info->getFileType();
    }

    /**
    * Bet BIT ness. Valid only if the file is a valid binary
    */
    BITNess getBITNess(PEHANDLE p_PEHandle)
    {
        PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
        l_PEInfo->readHeaderData();

        return l_PEInfo->m_pe_headers_info->getBITNess();
    }

    /**
    * Get Does header. Valid only if the file is a valid binary
    */
    IMAGE_DOS_HEADER getDOSHeader(PEHANDLE p_PEHandle)
    {

        PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
        l_PEInfo->readHeaderData();

        return l_PEInfo->m_pe_headers_info->getDOSHeader();
    }

    /**
    * Get File header. Valid only if the file is a valid binary
    */
    IMAGE_FILE_HEADER getFileHeader(PEHANDLE p_PEHandle)
    {

        PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
        l_PEInfo->readHeaderData();

        return l_PEInfo->m_pe_headers_info->getFileHeader();
    }

    /**
    * Get 64bit optinal header. Valid only if the file is 64bit binary
    */
    IMAGE_OPTIONAL_HEADER64 getOptHeader64(PEHANDLE p_PEHandle)
    {
        PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
        l_PEInfo->readHeaderData();

        return l_PEInfo->m_pe_headers_info->getOptHeader64();
    }

    /**
    * Get 32bit optinal header. Valid only if the file is 32bit binary
    */
    IMAGE_OPTIONAL_HEADER32 getOptHeader32(PEHANDLE p_PEHandle)
    {
        PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
        l_PEInfo->readHeaderData();

        return l_PEInfo->m_pe_headers_info->getOptHeader32();
    }

    /**
    * Get number of section headers. Valid only if the file is a valid binary
    */
    size_t getNoOfSectionHeaders(PEHANDLE p_PEHandle)
    {
        PEInfo * l_PEInfo = (PEInfo*)p_PEHandle;
        l_PEInfo->readHeaderData();

        return l_PEInfo->m_pe_headers_info->getNoOfSections();
    }

    /**
    * Allocates buffer for section headers and returns the data in the
    * buffer allocated. Caller must free the buffer with free call once
    * client is done with using the buffer.
    * Also copies number of sections in the p_no_of_sections parameter
    */
    IMAGE_SECTION_HEADER* getSectionHeaders(PEHANDLE p_PEHandle, size_t & p_no_of_sections)
    {

        PEInfo * l_pe_info = (PEInfo*)p_PEHandle;
        l_pe_info->readHeaderData();

        p_no_of_sections = getNoOfSectionHeaders(p_PEHandle);
        size_t l_req_size = p_no_of_sections * sizeof(IMAGE_SECTION_HEADER);
        IMAGE_SECTION_HEADER* l_buffer = (IMAGE_SECTION_HEADER*)malloc(l_req_size);
        memcpy_s(l_buffer, l_req_size, l_pe_info->m_pe_headers_info->m_sect_header_start, l_req_size);

        return l_buffer;
    }
}