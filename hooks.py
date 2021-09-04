import os
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

ROOT_FOLDER = "docs"

def build_onepage(*args, **kwargs):
    mkdocs = load(open("mkdocs.yml"), Loader=Loader)
    files = mkdocs['nav']

    # Remove index.md file
    files.remove('index.md')

    # If exists, remove one.md to avoid recursion loop
    if 'one.md' in files:
        files.remove('one.md')

    with open(ROOT_FOLDER + os.sep + "one.md", "w") as outfile:
        for file in files :
            # Only use MD files
            if file.endswith('.md'):
                # Replace '_' with ',' except if last occurence, then '&'.
                cleanName = file[:-3].replace('_',', ').capitalize().rsplit(', ',1)
                amp = " & "
                # Add header markup + linebreaks
                outfile.write("\n## " + amp.join( cleanName ) + "\n\n")
                with open(ROOT_FOLDER + os.sep + file) as mdfile:
                    for line in mdfile:
                        outfile.write( line ) 
