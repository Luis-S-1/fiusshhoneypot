installing git on windows:

Install

    Download the Git for Windows installer.
    Run the installer. Click "Next" four times (two times if you've previously installed Git). You don't need to change anything in the Information, Location, Components, or Start Menu screens.
    For each configuration screen, select the appropriate option and click "Next":
        Choosing the default editor used by git: select "Use the Nano editor by default" from the dropdown menu (you will need to scroll up to find it)
        Adjusting the name of the initial branch in new repositories: select "Let Git decide"
        Adjusting your PATH environment: select "Git from the command line and also from 3rd-party software" (if you don't do this Git Bash will not work properly, requiring you to remove the Git Bash installation, re-run the installer and to select the "Git from the command line and also from 3rd-party software" option.)
        Choosing the SSH executable: select "Use bundled OpenSSH"
        Choosing HTTPS transport backend: select "Use the native Windows Secure Channel Library"
        Configuring the line ending conversion: select "Checkout Windows-style, commit Unix-style line endings"
        Configuring the terminal emulator to use with GitBash: select "Use Windows' default console window"  ***Use MinTTY instead if you have some Linux experience***
        Choose the default behavior of `git pull`: select "Default (fast-forward or merge)"
        Choose a credential helper": select "Git Credential Manager"
        Configuring extra options": check the box for "Enable file system caching"
    Click "Install".
    Click on "Finish" or "Next".
    If your "HOME" environment variable is not set (or you don't know what this is):
        Open command prompt (Open the Start Menu, type cmd in the search box, and press Enter)
        Type the following line into the command prompt window exactly as shown:

        setx HOME "%USERPROFILE%"
        Press Enter, you should see SUCCESS: Specified value was saved.
        Quit command prompt by typing exit and pressing Enter

This will provide you with both Git and Bash in the Git Bash program.
Verify

    Open the GitBash application
    Type git --version and press Enter
    You should see a message reporting the version number


SOURCE: https://libguides.ucmerced.edu/software-carpentry/git/install
