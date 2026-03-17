from typing import TypedDict


class State():
    def __init__(self):
        self.num = 0
        self.name = "xxx"
    name: str
    num:int

def fun(state:State):
    state.num+=1

def display(state:State):
    print(state.name)
    print(state.num)

slang_dict = {"xxx":3}

class State(TypedDict):
    num: int
    name: str
def fun_dic(s_dict:dict):
    s_dict["xxx"]+=1
def fun_state(state:State):
    state["num"]+=1
if __name__ == "__main__":
    state = State(num=1,name="xxx")
    fun_state(state)
    print(state)