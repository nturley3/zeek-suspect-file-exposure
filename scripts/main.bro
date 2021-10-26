##! Detect access to suspicious exposed web server files

@load base/utils/site
@load base/utils/urls
@load base/frameworks/notice

module HTTPFileExposure;

export {

    redef enum Notice::Type += {
        ## Indicates that a MS Office suspicious file was accessed
        ## e.g. a Microsoft Access Database
        Office_File,
        ## Indicates that a database-type file was accessed
        ## e.g. a SQL dump file
        Database_File,
        ## Indicates that a common sensitive file was accessed
        ## e.g. a web server .htpasswd file
        Sensitive_File,
        ## Indicates that exposed source files were accessed
        ## e.g. a web server .phps file
        SourceCode_File
    };

    ## Defines the HTTP status codes we are interested in when detecting
    ## suspicious file access
    global success_status_codes: set[count] = {
        200,
        201,
        202,
        203,
        204,
        205,
        206,
        207,
        208,
        226,
        304
    };

    ## Regular expression to match direct sensitive files
    const suspicious_direct_sensitive_filenames = 
        /[pP][hH][pP]\.[iI][nN][iI]$/ | 
        /[aA][pP][pP][lL][iI][cC][aA][tT][iI][oO][nN]-[cC][oO][nN][fF][iI][gG]\.[pP][hH][pP]$/ |
        /[cC][oO][nN][nN][eE][cC][tT][iI][oO][nN]\.[iI][nN][cC]$/ |
        /[dD][aA][tT][aA][bB][aA][sS][eE]\.[cC][fF][gG]$/ |
        /[dD][aA][tT][aA][bB][aA][sS][eE]\.[cC][oO][nN][fF][iI][gG]$/ |
        /[iI][dD]_[rR][sS][aA]$/ |
        /[iI][dD]_[rR][sS][aA]\.[pP][uU][bB]$/ |
        /[pP][aA][sS][sS][wW][oO][rR][dD]\.[cC][fF][gG]$/ |
        /[pP][aA][sS][sS][wW][dD]\.[cC][fF][gG]$/ |
        /[pP][aA][sS][sS][wW][dD]\.[tT][xX][tT]$/ |
        /[pP][aA][sS][sS][wW][oO][rR][dD]\.[tT][xX][tT]$/ |
        /[pP][hH][pP][iI][nN][fF][oO]\.[pP][hH][pP]$/ |
        /[wW][eE][bB]\.[cC][oO][nN][fF][iI][gG]$/ |
        /.*\.[pP][hH][pP]\.[oO][lL][dD]$/ |
        /[wW][pP]-[cC][oO][nN][fF][iI][gG]\.[pP][hH][pP]$/ &redef;

    ## Regular expression to match common suspicious file extensions
    const suspicious_file_extensions = 
        /[dD][mM][pP]$/ | 
        /[dD][sS]_[sS][tT][oO][rR][eE]$/ |
        /[aA][sS][aA]$/ |
        /[bB][aA][cC][kK][uU][pP]$/ |
        /[bB][aA][kK]$/ |
        /[bB][aA][sS][hH]_[hH][iI][sS][tT][oO][rR][yY]$/ |
        /[hH][iI][sS][tT][oO][rR][yY]$/ |
        /[hH][tT][aA][cC][cC][eE][sS][sS]$/ |
        /[hH][tT][pP][aA][sS][sS][wW][dD]$/ |
        /[bB][cC][kK]$/ |
        /[bB][kK][fF]$/ |
        /[cC][fF][gG]$/ |
        /[cC][oO][nN][fF]$/ |
        /[cC][oO][nN][fF][iI][gG]$/ |
        /[cC][rR][tT]$/ |
        /[dD][aA][tT]$/ |
        /[dD][eE][fF][aA][uU][lL][tT]$/ |
        /[iI][nN][cC]$/ |
        /[iI][nN][fF]$/ |
        /[iI][nN][iI]$/ |
        /[iI][nN][sS]$/ |
        /[iI][sS][pP]$/ |
        /[lL][oO][gG]$/ |
        /[oO][lL][dD]$/ |
        /[oO][rR][iI][gG]$/ |
        /[pP][aA][sS][sS][wW][oO][rR][dD]$/ |
        /[pP][aA][sS][sS][wW][oO][rR][dD][sS]$/ |
        /[pP][sS][wW]$/ |
        /[qQ][iI][cC]$/ |
        /[rR][eE][gG]$/ |
        /[sS][aA][vV]$/ &redef;

    ## Regular expression to match exposure of common databases by extension
    const suspicious_db_file_extensions = 
        /[sS][qQ][lL]$/ | 
        /[dD][bB]$/ |
        /[pP][dD][bB]$/ |
        /[dD][bB][kK]$/ |
        /[dD][bB][sS]$/ |
        /[dD][bB][xX]$/ |
        /[eE][dD][bB]$/ |
        /[fF][rR][mM]$/ |
        /[jJ][oO][rR]$/ |
        /[lL][dD][fF]$/ |
        /[qQ][rR][uU]$/ |
        /[sS][qQ][lL][iI][tT][eE]$/ &redef;

    ## Regular expression to match exposure of common source files
    const suspicious_source_file_extensions = 
        /[pP][hH][pP][sS]$/ | 
        /[bB][aA][tT]$/ |
        /[cC][mM][dD]$/ |
        /[jJ][aA][vV][aA]$/ |
        /[pP][eE][rR][lL]$/ |
        /[pP][sS]1$/ |
        /[pP][yY]$/ |
        /[sS][oO][uU][rR][cC][eE]$/ |
        /[sS][rR][cC]$/ |
        /[vV][bB]$/ |
        /[vV][bB][sS]$/ &redef;

    ## Regular expression to match exposure of common archives
    const suspicious_archive_file_extensions = 
        /[zZ][iI][pP]$/ | 
        /7[zZ]$/ |
        /[zZ]$/ |
        /[bB][zZ]2$/ |
        /[gG][zZ]$/ |
        /[rR][aA][rR]$/ |
        /[tT][aA][rR]$/ |
        /[tT][aA][rR]\.[gG][zZ]$/ |
        /[tT][gG][zZ]$/ &redef;

    ## Regular expression to match exposure of common MS Office databse files by extension
    const suspicious_office_file_extensions = 
        /[aA][cC][cC][dD][bB]$/ |
        /[aA][cC][cC][dD][cC]$/ |
        /[aA][cC][cC][dD][eE]$/ |
        /[aA][cC][cC][dD][rR]$/ |
        /[iI][aA][fF]$/ |
        /[lL][aA][cC][cC][dD][bB]$/ |
        /[mM][dD][bB]$/ |
        /[mM][dD][eE]$/ |
        /[mM][dD][fF]$/ |
        /[oO][aA][bB]$/ |
        /[oO][lL][mM]$/ |
        /[oO][sS][tT]$/ |
        /[pP][aA][bB]$/ |
        /[pP][sS][tT]$/ &redef;
}

# TODO: Add mime/type detection where appropriate

function gen_file_http_notice(c: connection, code: count, reason: string, note: Notice::Type, msg: string)
{
    # Check for field existence and assign defaults
    local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
    # local method = c$http?$method ? c$http$method : "UNKNOWN";
    local uri = c$http?$uri ? c$http$uri : "UNKNOWN";

    NOTICE([$note=note,
            $msg=fmt("%s", msg),
            $sub=fmt("%s%s (%s %s)", respHost, uri, code, reason),
            $conn=c,
            $identifier=cat(c$id$resp_h, c$id$resp_p, c$http$uri),
            $suppress_for=4hr]);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    if(Site::is_local_addr(c$id$resp_h) && c$http?$status_code && c$http?$uri && code in HTTPFileExposure::success_status_codes)
    {
        local fname: string;
        local fext: string;
        local uri: URI;
        uri = decompose_uri(c$http$uri);

        if ( (uri?$file_name && suspicious_direct_sensitive_filenames in uri$file_name) || (uri?$file_ext && suspicious_file_extensions in uri$file_ext) )
        {
            gen_file_http_notice(c, code, reason, Sensitive_File, "Access to a potentially sensitive file was detected");
        }
        else if ( uri?$file_ext && suspicious_db_file_extensions in uri$file_ext)
        {
            gen_file_http_notice(c, code, reason, Database_File, "Access to a potentially sensitive database file was detected");
        }
        else if ( uri?$file_ext && suspicious_office_file_extensions in uri$file_ext)
        {
            gen_file_http_notice(c, code, reason, Office_File, "Access to a potentially sensitive MS Office file was detected");
        }
        else if ( uri?$file_ext && suspicious_source_file_extensions in uri$file_ext)
        {
            gen_file_http_notice(c, code, reason, SourceCode_File, "Access to a potentially sensitive source code file was detected");
        }
        else
        {
            return;
        }
    }
}

