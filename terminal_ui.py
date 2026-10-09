"""Small curses UI. Never renders source control sequences as terminal commands."""
import curses
import locale
import sys
import unicodedata

def safe(text):
 return ''.join(c if (c.isprintable() and unicodedata.category(c) not in ('Cf','Cs')) else ' ' for c in str(text))
class UI:
 def __init__(self,screen,title):
  self.s=screen;self.title=title;screen.keypad(True)
  try:curses.curs_set(0)
  except curses.error:pass
  if curses.has_colors():
   curses.start_color();curses.use_default_colors()
   curses.init_pair(1,curses.COLOR_CYAN,-1);curses.init_pair(2,curses.COLOR_BLACK,curses.COLOR_CYAN)
 def put(self,y,x,text,attr=0):
  h,w=self.s.getmaxyx()
  if 0<=y<h and x<w-1:
   try:self.s.addnstr(y,x,safe(text),max(0,w-x-1),attr)
   except curses.error:pass
 def draw(self,subtitle,rows,selected=0,footer='↑↓ Select  Enter Open  Esc Back',offset=0):
  self.s.erase();h,w=self.s.getmaxyx()
  color=curses.color_pair(1) if curses.has_colors() else curses.A_BOLD
  self.put(0,0,'█ '+self.title+' █',color);self.put(1,0,'─'*max(0,w-1),color)
  self.put(2,1,subtitle,curses.A_BOLD)
  for n,row in enumerate(rows[offset:offset+max(1,h-6)]):
   index=n+offset;attr=(curses.color_pair(2) if curses.has_colors() else curses.A_REVERSE) if index==selected else 0
   self.put(n+4,1,('▶ ' if index==selected else '  ')+row,attr)
  self.put(h-2,0,'─'*max(0,w-1),color);self.put(h-1,1,footer);self.s.refresh()
 def menu(self,subtitle,rows):
  if not rows:rows=['(empty)']
  index=0
  while True:
   h,w=self.s.getmaxyx();page=max(1,h-6);offset=max(0,index-page+1)
   self.draw(subtitle,rows,index,offset=offset);k=self.s.get_wch()
   if k in (curses.KEY_UP,'k'):index=(index-1)%len(rows)
   elif k in (curses.KEY_DOWN,'j'):index=(index+1)%len(rows)
   elif k in ('\n','\r',curses.KEY_ENTER):return index
   elif k in ('\x1b','q'):return None
 def prompt(self,label,secret=False):
  value=''
  try:curses.curs_set(1)
  except curses.error:pass
  try:
   while True:
    self.draw(label,[],footer='Enter Accept  Esc Cancel  Backspace Delete')
    shown='*'*len(value) if secret else safe(value);self.put(4,2,shown[-max(1,self.s.getmaxyx()[1]-5):]);self.s.refresh()
    k=self.s.get_wch()
    if k in ('\n','\r',curses.KEY_ENTER):return value
    if k=='\x1b':return None
    if k in (curses.KEY_BACKSPACE,'\x7f','\b'):value=value[:-1]
    elif isinstance(k,str) and k.isprintable() and len(value)<4096:value+=k
  finally:
   try:curses.curs_set(0)
   except curses.error:pass
 def confirm(self,text):return self.menu(text,['Cancel','Yes, continue'])==1
 def message(self,text):
  lines=[]
  for line in str(text).splitlines():
   width=max(10,self.s.getmaxyx()[1]-6);lines.extend([line[i:i+width] for i in range(0,max(1,len(line)),width)])
  offset=0
  while True:
   self.draw('',lines,-1,footer='↑↓ Scroll  Enter/Esc Back',offset=offset);k=self.s.get_wch()
   if k in ('\n','\r','\x1b','q',curses.KEY_ENTER):return
   if k==curses.KEY_DOWN:offset=min(max(0,len(lines)-1),offset+1)
   elif k==curses.KEY_UP:offset=max(0,offset-1)
 def external(self,fn):
  curses.def_prog_mode();curses.endwin()
  try:return fn()
  finally:curses.reset_prog_mode();self.s.refresh()

def run(title,callback):
 if not sys.stdin.isatty() or not sys.stdout.isatty():
  print('Terminal mode needs an interactive TTY. Connect with an interactive SSH session; use --gui for desktop mode.');return 2
 locale.setlocale(locale.LC_ALL,'')
 try:return curses.wrapper(lambda s:callback(UI(s,title))) or 0
 except curses.error:
  print('Cannot initialize the terminal. Use a supported TERM and an interactive SSH session.');return 2
 except KeyboardInterrupt:return 130
