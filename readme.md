# first install the virtual environment package
pip install virtualenv

# then you make a enviroment, I name it 810_server, you can name it whatever
virtualenv 810_server

# In windows, navigate to the Scripts directory and run the activate command / script
810_server/Scripts/activate

# then you install the packages for this program with the following command
pip install -r server_requirements.txt