#include "PEParserImpl.h"

using namespace PEParser;

/**
* PEInfo constructor. Takes handles to the file as input
*/
PEInfo::PEInfo(HANDLE const & p_fileHandle,
               HANDLE const & p_filemapping_handle,
               PVOID const p_view_ponter) 
    : m_pe_file_handle(p_fileHandle),
      m_filemapping_handle(p_filemapping_handle),
      m_view_pointer(p_view_ponter)
{
    m_pe_headers_info = new PEHeaderInfo();
}

/**
* Destructor
*/
PEInfo::~PEInfo()
{
    delete m_pe_headers_info;
    CloseHandle(m_pe_file_handle);
    CloseHandle(m_filemapping_handle);
    UnmapViewOfFile(m_view_pointer);
}

/**
* Read header data of the PE file.
*/
void PEInfo::readHeaderData()
{
    if (m_cached_data.count(CachedData::PE_HEADER_INFO) < 0)
    {
        /* We already have PE header information. Nothign to do */
        return;
    }

    /* Reset Cache */
    m_pe_headers_info->reset();

    try
    {
        /* Get DOS Header */
        getDOSHeader();

        /* Get NT Header (including Optinal Header) */
        getNTHeader();

        /* Get Section Headers */
        getSectionHeaders();

        /* Mark cached */
        m_cached_data.insert(CachedData::PE_HEADER_INFO);
    }
    catch (PEParser::PEParserException const & l_exception)
    {
        /* Reset Cache  */
        m_pe_headers_info->reset();
        throw l_exception;
    }
}

/**
* Read DOS header
*/
void PEInfo::getDOSHeader()
{
    /* Initialize header information */
    PIMAGE_DOS_HEADER l_dos_header = (PIMAGE_DOS_HEADER)m_view_pointer;
    if (IMAGE_DOS_SIGNATURE != l_dos_header->e_magic)
    {
        m_pe_headers_info->setPEFileType(PEFileType::NOT_A_PE_FILE);
        return;
    }

    /* Set DOS Header */
    m_pe_headers_info->setDOSHeader(*l_dos_header);
    m_pe_headers_info->hasDOSHeader(true);
}

/**
* Read NT headers
* TODO: This is not correct. We are blindly redaing data sections (16)
*/
void PEInfo::getNTHeader()
{
    /* Return if no DOS header */
    if (!m_pe_headers_info->hasDOSHeader())
    {
        return;
    }

    /* Seek to File Header position */
    IMAGE_DOS_HEADER l_dos_header = m_pe_headers_info->getDOSHeader();
    LONG l_elf_position = l_dos_header.e_lfanew;

    /* Assume it is 32-bit image as of now */
    PIMAGE_NT_HEADERS32 l_nt_heade_ptr = PIMAGE_NT_HEADERS32((char*)m_view_pointer + l_dos_header.e_lfanew);
    if (IMAGE_NT_SIGNATURE != l_nt_heade_ptr->Signature)
    {
        m_pe_headers_info->setPEFileType(PEFileType::NOT_A_PE_FILE);
        return;
    }

    /* Set File Header : Same for both 32bit and 64bit */
    m_pe_headers_info->setFileHeader(l_nt_heade_ptr->FileHeader);
    m_pe_headers_info->hasNTHeader(true);

    /* Get Image Type */
    WORD l_characterstics = l_nt_heade_ptr->FileHeader.Characteristics;
    if (!(IMAGE_FILE_EXECUTABLE_IMAGE & l_characterstics))
    {
        /* We don't support currently */
        m_pe_headers_info->setPEFileType(PEFileType::NOT_SUPPORTED);
    }

    if (IMAGE_FILE_DLL & l_characterstics)
    {
        m_pe_headers_info->setPEFileType(PEFileType::DLL_FILE);
    }
    else if (IMAGE_FILE_SYSTEM & l_characterstics)
    {
        m_pe_headers_info->setPEFileType(PEFileType::NOT_SUPPORTED);
    }
    else
    {
        /* TODO: EXE ???? */
        m_pe_headers_info->setPEFileType(PEFileType::EXE_FILE);
    }

    /* Get BITNess (32 or 64) */
    WORD l_opt_header_magic = l_nt_heade_ptr->OptionalHeader.Magic;
    if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == l_opt_header_magic)
    {
        m_pe_headers_info->setBITNess(BITNess::BITNESS_32);
        m_pe_headers_info->setOptHeader32(l_nt_heade_ptr->OptionalHeader);
    }
    else if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == l_opt_header_magic)
    {
        m_pe_headers_info->setBITNess(BITNess::BITNESS_64);
        m_pe_headers_info->setOptHeader64(((PIMAGE_NT_HEADERS64)l_nt_heade_ptr)->OptionalHeader);
    }
}

/**
* Read PE section headers and store them on heap.
* Heap is required as we don't the numer of section in advance.
*/
void PEInfo::getSectionHeaders()
{
    PEFileType l_pe_file_type = m_pe_headers_info->getFileType();
    if (!IsSupportedPEType(l_pe_file_type))
    {
        return;
    }

    m_pe_headers_info->m_no_sections = m_pe_headers_info->m_file_header.NumberOfSections;
    if (BITNess::BITNESS_32 == m_pe_headers_info->getBITNess())
    {
        m_pe_headers_info->m_sect_header_start 
            = (PIMAGE_SECTION_HEADER) ((char*)m_view_pointer + 
                                       m_pe_headers_info->m_dos_header.e_lfanew +
                                       sizeof(IMAGE_NT_HEADERS32));
    }
    else
    {
        m_pe_headers_info->m_sect_header_start
            = (PIMAGE_SECTION_HEADER)((char*)m_view_pointer +
                                      m_pe_headers_info->m_dos_header.e_lfanew +
                                      sizeof(IMAGE_NT_HEADERS64));
    }

    /* Just to debug the data, iterate on each of the section header */
    for (int l_counter = 0; l_counter < m_pe_headers_info->m_no_sections; l_counter++)
    {
        PIMAGE_SECTION_HEADER l_sect_header = m_pe_headers_info->m_sect_header_start + l_counter;
        string l_sectionName = string((char*)l_sect_header->Name);
    }
}

/**
* Constructor
*/
PEHeaderInfo::PEHeaderInfo()
{
    m_has_dos_header = false;
    m_has_nt_header = false;
    m_pe_type = PEFileType::NOT_SUPPORTED;
    m_bitness = BITNess::BITNESS_UNKNOWN;
    m_no_sections = 0;
    m_sect_header_start = NULL;
}

/**
* Destructor
*/
PEHeaderInfo::~PEHeaderInfo()
{
    reset();
}

/**
* Reset the PE header data.
*/
void PEHeaderInfo::reset()
{
    m_has_dos_header = false;
    m_has_nt_header = false;
    m_pe_type = PEFileType::NOT_SUPPORTED;
    m_bitness = BITNess::BITNESS_UNKNOWN;
    m_no_sections = 0;
    m_sect_header_start = NULL;
}