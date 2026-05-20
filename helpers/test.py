import re 
# pyrefly: ignore [missing-import]
from manual import Manual

def test_func(x_var:str) :
    

    opt = {}
    for k,v in Manual.dorking_commands.get('findFiles').items():
        
        print(v.get('example'))


test_func("pdfs")

