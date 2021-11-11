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
        /php\.ini$/i | 
        /application-config\.php$/i |
        /connection\.inc$/i |
        /database.cfg$/i |
        /database.config$/i |
        /id_rsa$/i |
        /id_rsa\.pub$i/i |
        /password\.cfg$/i |
        /passwd\.cfg$/i |
        /passwd\.txt$/i |
        /password\.txt$/i |
        /phpinfo\.php$/i |
        /web\.config$/i |
        /.*\.php\.old$/i |
        /wp-config\.php$/i &redef;

    ## Regular expression to match common suspicious file extensions
    const suspicious_file_extensions = 
        /dmp$/i | 
        /ds_store$/i |
        /asa$/i |
        /backup$/i |
        /bak$/i |
        /bash_history$/i |
        /history$/i |
        /htaccess$/i |
        /htpasswd$/i |
        /bck$/i |
        /bkf$/i |
        /cfg$/i |
        /conf$/i |
        /config$/i |
        /crt$/i |
        /dat$/i |
        /default$/i |
        /inc$/i |
        /inf$/i |
        /ini$/i |
        /ins$/i |
        /isp$/i |
        /log$/i |
        /old$/i |
        /orig$/i |
        /password$/i |
        /passwords$/i |
        /psw$/i |
        /qic$/i |
        /reg$/i |
        /sav$/i &redef;

    ## Regular expression to match exposure of common databases by extension
    const suspicious_db_file_extensions = 
        /sql$/i | 
        /db$/i |
        /pdb$/i |
        /dbk$/i |
        /dbs$/i |
        /dbx$/i |
        /edb$/i |
        /frm$/i |
        /jor$/i |
        /ldf$/i |
        /qru$/i |
        /sqlite$/i &redef;

    ## Regular expression to match exposure of common source files
    const suspicious_source_file_extensions = 
        /phps$/i | 
        /bat$/i |
        /cmd$/i |
        /java$/i |
        /perl$/i |
        /ps1$/i |
        /py$/i |
        /source$/i |
        /src$/i |
        /vb$/i |
        /vbs$/i &redef;

    ## Regular expression to match exposure of common archives
    const suspicious_archive_file_extensions = 
        /zip$/i | 
        /7z$/i |
        /z$/i |
        /bz2$/i |
        /gz$/i |
        /rar$/i |
        /tar$/i |
        /tar\.gz$/i |
        /tgz$/ &redef;

    ## Regular expression to match exposure of common MS Office databse files by extension
    const suspicious_office_file_extensions = 
        /accdb$/i |
        /accdc$/i |
        /accde$/i |
        /accdr$/i |
        /iaf$/i |
        /laccdb$/i |
        /mdb$/i |
        /mde$/i |
        /mdf$/i |
        /oab$/i |
        /olm$/i |
        /ost$/i |
        /pab$/i |
        /pst$/ &redef;
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

