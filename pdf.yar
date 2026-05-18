rule PDF_JavaScript {
    meta: description = "PDF contains JavaScript" severity = "MEDIUM"
    strings: $s1 = "/JavaScript" nocase  $s2 = "/JS " nocase
    condition: any of them
}
rule PDF_OpenAction {
    meta: description = "PDF triggers action on open" severity = "MEDIUM"
    strings: $s1 = "/OpenAction"  $s2 = "/AA "
    condition: any of them
}
rule PDF_Launch {
    meta: description = "PDF attempts to launch external process" severity = "HIGH"
    strings: $s1 = "/Launch"
    condition: $s1
}
rule PDF_EmbeddedFile {
    meta: description = "PDF contains embedded file" severity = "LOW"
    strings: $s1 = "/EmbeddedFile"
    condition: $s1
}
rule PDF_Obfuscation {
    meta: description = "PDF uses obfuscation techniques" severity = "MEDIUM"
    strings: $s1 = "fromCharCode" nocase  $s2 = "unescape(" nocase  $s3 = "eval(" nocase
    condition: any of them
}
rule PDF_ExternalURI {
    meta: description = "PDF contains external URI links" severity = "INFO"
    strings: $s1 = "/URI" nocase
    condition: $s1
}
