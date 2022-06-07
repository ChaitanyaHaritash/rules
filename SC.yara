rule APT_SideCopy_All{
    meta:
      description = "Rule to hunt SideCopy Payloads based on PDB paths"
      author = "Chaitanya Haritash/Sameer Patil"
      reference = "https://www.seqrite.com/blog/seqrite-uncovers-second-wave-of-operation-sidecopy-targeting-indian-critical-infrastructure-psus/"
      date = "12-08-2021"
    strings:
        $mz = "MZ"
        $str1 = "G:\\VP-S-Fin\\"
        $str2 = "E:\\LFD\\Botnet\\"
        $str3 = "D:\\RATS\\"
        $str4 = "C:\\Users\\Jadhav\\Source\\Repos\\"
        $str5 = "E:\\cplusplus\\"
        $str6 = "G:\\VPN-Update\\"
        $str7 = "c:\\users\\ajay sharma\\documents\\visual studio 2015\\"
        $str8 = "C:\\Users\\neymar\\repos\\"
        $str9 = "C:\\Users\\Administrator\\Desktop\\crptr\\"
        $str10 = "F:\\Packers\\"
        $str11 = "E:\\OpenRATs\\"
        $str12 = "D:\\C\\Proj\\"
        $str13 = "D:\\Pkgs\\Project\\"
        $str14 = "e:\\core-projects\\"
        $str15 = "g:\\new tgvp\\shobi-tgr\\"
        $str16 = "g:\\rwlbmarivs\\"
        $str17 = "c:\\Users\\Zombie\\Desktop\\"
        $str18 = "E:\\csharp\\"
        $str19 = "C:\\Users\\riamz\\Downloads\\"
        $str20 = "C:\\Users\\riamz\\Desktop\\"
        $str21 = "C:\\Users\\DIRILIS\\"
        $str22 = "C:\\Users\\Apolo Jones\\"
    condition:
        $mz at 0 and any of ($str*)
}
