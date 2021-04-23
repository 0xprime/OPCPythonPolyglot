rule OPCPythonPolyglot
{
        meta:
                $author = "0xPrime"
                $comment = "OPC/Python polyglot"

        strings:
                $opcidentifier1 = ".xml.relsPK"
                $opcidentifier2 = "[Content_Types].xmlPK"
                $pythonfile = "__main__.pyPK"

        condition:
                all of them
}
