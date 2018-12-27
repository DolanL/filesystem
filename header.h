#include <cstdio>
#include <QDirIterator>
#include <QFileSystemModel>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <QThread>
#include <vector>
#include <windows.h>

class ilogger
{
public:
    virtual void log(const std::string& message) = 0;
    virtual ~ilogger() {;}
};

class antivirusScaner : public QThread {
    Q_OBJECT
signals:
    void send_for_writing(QString str);
    void finish_checking_directory();
    void finish_checking_registry();

private:
    int counter=0;
    std::vector<std::string> virus_strings;

    void run() {
        if(directory) {
            checking_dyrectory(name_of_scan);
            emit finish_checking_directory();
        }
        else {
            check_registry();
            emit finish_checking_registry();
        }
    }

    void read_data_of_dangerous_files() {
        std::ifstream fin("../bases/data.txt");
        std::string str;

        while (std::getline(fin, str)) {
            virus_strings.push_back(str);
        }
        fin.close();
    }

    void checking_dyrectory(const QString & checking) {
        QDirIterator it(checking);

        while (it.hasNext() ) {
            QString str1 = QFileInfo(it.path()).absoluteFilePath().toUtf8().constData();
            str1 += "/.";
            QString str2 = QFileInfo(it.path()).absoluteFilePath().toUtf8().constData();
            str2 += "/..";
            QString str3 = it.next();
            if(str3 == str1 || str3 == str2) continue;

            if (QFileInfo(str3).isDir()) {
                checking_dyrectory(it.filePath());
            }
            else {
                std::string name = QFileInfo(str3).fileName().toUtf8().constData(), extension = QFileInfo(str3).completeSuffix().toUtf8().constData();
                std::cout << extension;
                if (extension == "exe" || extension == "rar") {
                    if (is_dangerous(QFileInfo(str3).absoluteFilePath().toUtf8().constData())) {
                        move_file(QFileInfo(str3).absoluteFilePath().toUtf8().constData(), name);
                    }
                }
            }
        }
    }

    bool checking_file(std::string & buf) {

        for (auto i : virus_strings) {
            if (buf.find(i) != std::string::npos) {
                emit send_for_writing("This file is dangerous! \n");
                return true;
            }
        }
        emit send_for_writing("No problem with this file" );
        return false;
    }

    bool is_dangerous(std::string name) {
        bool succsess = false;
        std::ifstream ifile(name, std::ofstream::binary);
        if (ifile.is_open()) {
            std::string string="\n " + name + " is cheking now... \n";
            emit send_for_writing(QString::fromStdString(string));

            ifile.seekg(0, ifile.end);
            int length = ifile.tellg();
            ifile.seekg(0, ifile.beg);
            char * buffer = new char[++length];
            buffer[length - 1] = '\0';
            ifile.read((char*)buffer, length);

            std::string str;
            for (auto i = 0; i < length; ++i) {
                str += buffer[i];
            }

            succsess = checking_file(str);

            delete[] buffer;
            ifile.close();
        }
        else {
            std::string string="\n " + name + " has been already deleted or does not exist \n";
            emit send_for_writing(QString::fromStdString(string));
        }
        return succsess;
    }

    std::wstring to_LPCWSTR(const std::string& s)
    {
        int len;
        int slength = (int)s.length() + 1;
        len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
        wchar_t* buf = new wchar_t[len];
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
        std::wstring r(buf);
        delete[] buf;
        return r;
    }

    void check_registry() {
        HKEY hKey;
        std::vector< std::pair<std::string, std::string> > strings_of_registry;

        if (RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), NULL, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
        {
            TCHAR lpData[1024] = { 0 };
            TCHAR data[1024] = { 0 };
            std::string str1, str2;
            DWORD buffersize = sizeof(lpData);
            DWORD num, MaxValueNameLen;

            RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &num, &MaxValueNameLen, NULL, NULL, NULL);

            for (DWORD i = 0; i < num; i++) {
                buffersize = MaxValueNameLen + 1;
                lpData[0] = '\0';
                data[0] = '\0';
                RegEnumValue(hKey, i, lpData, &buffersize, NULL, NULL, NULL, NULL);

                buffersize = 256;
                RegQueryValueEx(hKey, lpData, NULL, NULL, (LPBYTE)data, &buffersize);

                for (auto i = 0; lpData[i] != '\0'; ++i) {
                    str1 += lpData[i];
                }

                auto index = 0;
                if (data[0] == '\"') {
                    index = 1;
                }
                while (data[index] != '.' || data[index + 1] != 'e' || data[index + 2] != 'x' || data[index + 3] != 'e') {
                    str2 += data[index++];
                }
                str2 += data[index];
                str2 += data[index + 1];
                str2 += data[index + 2];
                str2 += data[index + 3];

                strings_of_registry.push_back(std::make_pair(str1, str2));
                str1.clear();
                str2.clear();
            }
        }

        for (auto i : strings_of_registry) {
            std::string str="\n Value: " + i.first + "\n Key: " + i.second + "\n";
            emit send_for_writing(QString::fromStdString(str));

            if (is_dangerous(i.second)) {
                std::wstring stemp1 = to_LPCWSTR(i.first);
                std::wstring stemp2 = to_LPCWSTR(i.second);
                LPCWSTR str1 = stemp1.c_str();
                LPCWSTR str2 = stemp2.c_str();
                valuesAndKeys.push_back(QString::fromUtf16((const ushort*)str2));
                ++counter;

                //RegDeleteValue(hKey, str1);
                //RegDeleteKey(hKey, str2);
                //emit send_for_writing("This record has been deleted \n");

                //move_file(path(i.second).generic_string(), path(i.second).filename().generic_string());
            }
        }

        RegCloseKey(hKey);
    }

public:
    ilogger *logger;
    QString name_of_scan;
    bool directory;
    std::vector<QString> valuesAndKeys;

    void move_file(std::string filname, std::string name) {
        ++counter;
        const char * from, *to;
        from = filname.c_str();
        name = "carantin\\" + name;
        to = name.c_str();
        rename(from, to);

        emit send_for_writing("File has been moved in carantin \n");
    }

    int counter_()
    {
       return this->counter;
    }

    void new_count()
    {
        counter=0;
    }

    void set_logger(ilogger *_logger)
    {
        logger = _logger;
    }

    antivirusScaner() {
        read_data_of_dangerous_files();
    }
};
