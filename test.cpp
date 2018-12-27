#include "../include/header.h"
#include <QtTest/QtTest>

class Test : public QObject{
Q_OBJECT

public slots:
  void test_one();
  void test_two();
};

void Test::test_one()
{
  antivirusScaner scaner;
  scaner.new_count();
  scaner.directory = false;
  scaner.start();
  scaner.wait();
  QVERIFY(scaner.counter_() == 0);
}

void Test::test_two()
{
  antivirusScaner scaner;
  scaner.new_count();
  scaner.directory = true;
  scaner.name_of_scan = "C:\projects\filesystem";
  scaner.start();
  scaner.wait();
  QVERIFY(scaner.counter_() == 0);
}

QTEST_MAIN(Test)
#include "test.moc"
