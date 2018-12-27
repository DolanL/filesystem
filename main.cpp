#include "../include/mainwindow.h"
#include <QApplication>
#include <QDebug>
#include <QtGlobal>
#include <bitset>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.setWindowTitle("AN");
    w.setWindowIcon(QIcon(":/imgs/loggwp.bmp"));
    w.show();
    return a.exec();
}
