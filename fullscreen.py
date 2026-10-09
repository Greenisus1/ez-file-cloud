import subprocess,sys
from terminal_ui import run
ROWS = [('Receive files', ['python3', 'ezfilecloud.py', 'receive']), ('Send / retrieve files through original chooser', ['python3', 'ezfilecloud.py']), ('Scan receivers', ['python3', 'ezfilecloud.py', 'scan'])]
def session(ui):
 while True:
  n=ui.menu('EZ file cloud - original password-free LAN transfers',[r[0] for r in ROWS]+['Quit'])
  if n is None or n==len(ROWS):return
  if False and not ui.confirm('Continue? This runs the original script with its package/service/terms effects.'):continue
  ui.external(lambda:subprocess.run(ROWS[n][1],check=False))
  ui.message('Original command finished. No success claim is inferred. See its terminal output.')
if __name__=='__main__':raise SystemExit(run('ez-file-cloud',session))
