# PE-File-Visualiser


Instructions for use:

To run the script in the command line:

python getpe.pyc -i testfile.exe

It will produce file "testfile.exe.png" in the current folder.
You can specify the output filename in command line with parameter -o outfilename.
There is also a parameter "--scale" exists. By default it is set to 1 and you can run with another value:

python getpe.pyc -i testfile.exe -o resultfile.png --scale 2.5

And the size of the items on the drawing area will be increased by 2.5 times. You can find the examples with scaling 1 and 2 for 4 different files.
For example testfile2.exe is a self-extracting archive and you can see that the majority of the file is taken by overlay data.

You will also need to install Python's module "Pillow" for windows/linux.

Then it should work if these files are in current directory:
* getpe.pyc
* pefile.pyc
* Arial_Bold.ttf
