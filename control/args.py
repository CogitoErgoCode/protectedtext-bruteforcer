import os, sys, argparse

class Args:
    BANNER = """
  ___         _          _          _ _____        _   
 | _ \_ _ ___| |_ ___ __| |_ ___ __| |_   _|____ _| |_ 
 |  _/ '_/ _ \  _/ -_) _|  _/ -_) _` | | |/ -_) \ /  _|
 |_| |_|_\___/\__\___\__|\__\___\__,_| |_|\___/_\_\\__|
     | _ )_ _ _  _| |_ ___ / _|___ _ _ __ ___ _ _      
     | _ \ '_| || |  _/ -_)  _/ _ \ '_/ _/ -_) '_|     
     |___/_|  \_,_|\__\___|_| \___/_| \__\___|_|                     
"""

    intro = f"""{sys.platform} pid: {os.getppid()}\n{BANNER}
ptb  : ProtectedText.com Password Recovery tool
Blog : CogitoErgoCode.github.io/protectedText/
Usage: ptb.py [Option(s)] {{Argument specification}}

Options:
    -h,  --help     You're here ;)
    -v,  --version  Show Version Information
         --verbose  Increase Verbosity

Target Site Selection:
    -l,  --link <LINK>

Attack Options:
    -d,  --dictionary <WORDLIST>
    -b,  --bruteforce <min> <max>
    -c,  --character_set <0-9>

Example:
  ./ptb.py --link site -d wordlists\\10000.txt
  ./ptb.py --link site -d ~\\Desktop\\10000.txt --verbose
  ./ptb.py --link site -d %USERPROFILE%\\Desktop\\500.txt
  ./ptb.py --link site --bruteforce 1 4 -c 8
"""

    def __init__(self):
        parser = argparse.ArgumentParser(
            add_help = False, 
            prog     = "ptb"
        )
        
        parser.add_argument(
            "-h", "--help", 
            action = "store_true", 
            help   = "You are Here ..."
        )

        parser.add_argument(
            "-v", "--version", 
            action  = "version", 
            version = "%(prog)s 1.0", 
            help    = "Show Version Information"
        )

        parser.add_argument(
            "--verbose", 
            action = "store_true", 
            help   = "Increase Verbosity"
        )

        parser.add_argument(
            "-l", "--link",
            metavar  = ("<Link>"),
            type     = str,
            help     = "site link"
        )

        group = parser.add_mutually_exclusive_group()
        
        group.add_argument(
            "-d", "--dictionary",
            metavar = ("<Wordlist>"),
            type    = str,
            help    = "file path"
        )

        group.add_argument(
            "-b", "--bruteforce",
            metavar = ("<Min>", "<Max>"),
            nargs   = 2,
            type    = int,
            help    = "Character Range"
        )

        parser.add_argument(
            "-c", "--character_set",
            metavar = ("<0-9>"),
            type    = int,
            choices = range(10),
            # default = 3,
            help    = "Character Set"
        )

        self.__args = parser.parse_args()

    @property
    def dct_args(self):
        return vars(self.__args)

    def process(self):
        conditions = [
            self.dct_args.get("help"),
            not any(self.dct_args.values()),
            not (
                self.dct_args.get("dictionary") or \
                self.dct_args.get("bruteforce")
            ) 
        ]
        if any(conditions):
            print( type(self).intro )
            os._exit(0)

        if self.dct_args.get("bruteforce") and self.dct_args.get("character_set") is None:
            self.__args.character_set = 6
