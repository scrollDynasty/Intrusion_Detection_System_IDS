/********************************************************************************
** Form generated from reading UI file 'MainWindow.ui'
**
** Created by: Qt User Interface Compiler version 6.8.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTableView>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QAction *actionExit;
    QAction *actionAbout;
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QComboBox *comboBoxDevices;
    QPushButton *pushButtonStart;
    QPushButton *pushButtonStop;
    QSpacerItem *horizontalSpacer;
    QPushButton *pushButtonClear;
    QSplitter *splitter;
    QGroupBox *groupBox;
    QVBoxLayout *verticalLayout_2;
    QTableView *tableViewSuspiciousIP;
    QGroupBox *groupBox_2;
    QVBoxLayout *verticalLayout_3;
    QTextEdit *textEditLog;
    QMenuBar *menubar;
    QMenu *menu;
    QMenu *menu_2;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(800, 600);
        actionExit = new QAction(MainWindow);
        actionExit->setObjectName("actionExit");
        actionAbout = new QAction(MainWindow);
        actionAbout->setObjectName("actionAbout");
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName("centralwidget");
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName("verticalLayout");
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName("horizontalLayout");
        label = new QLabel(centralwidget);
        label->setObjectName("label");

        horizontalLayout->addWidget(label);

        comboBoxDevices = new QComboBox(centralwidget);
        comboBoxDevices->setObjectName("comboBoxDevices");
        comboBoxDevices->setMinimumSize(QSize(300, 0));

        horizontalLayout->addWidget(comboBoxDevices);

        pushButtonStart = new QPushButton(centralwidget);
        pushButtonStart->setObjectName("pushButtonStart");

        horizontalLayout->addWidget(pushButtonStart);

        pushButtonStop = new QPushButton(centralwidget);
        pushButtonStop->setObjectName("pushButtonStop");

        horizontalLayout->addWidget(pushButtonStop);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Policy::Expanding, QSizePolicy::Policy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        pushButtonClear = new QPushButton(centralwidget);
        pushButtonClear->setObjectName("pushButtonClear");

        horizontalLayout->addWidget(pushButtonClear);


        verticalLayout->addLayout(horizontalLayout);

        splitter = new QSplitter(centralwidget);
        splitter->setObjectName("splitter");
        splitter->setOrientation(Qt::Vertical);
        groupBox = new QGroupBox(splitter);
        groupBox->setObjectName("groupBox");
        verticalLayout_2 = new QVBoxLayout(groupBox);
        verticalLayout_2->setObjectName("verticalLayout_2");
        tableViewSuspiciousIP = new QTableView(groupBox);
        tableViewSuspiciousIP->setObjectName("tableViewSuspiciousIP");
        tableViewSuspiciousIP->setAlternatingRowColors(true);
        tableViewSuspiciousIP->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableViewSuspiciousIP->horizontalHeader()->setStretchLastSection(true);

        verticalLayout_2->addWidget(tableViewSuspiciousIP);

        splitter->addWidget(groupBox);
        groupBox_2 = new QGroupBox(splitter);
        groupBox_2->setObjectName("groupBox_2");
        verticalLayout_3 = new QVBoxLayout(groupBox_2);
        verticalLayout_3->setObjectName("verticalLayout_3");
        textEditLog = new QTextEdit(groupBox_2);
        textEditLog->setObjectName("textEditLog");
        textEditLog->setReadOnly(true);

        verticalLayout_3->addWidget(textEditLog);

        splitter->addWidget(groupBox_2);

        verticalLayout->addWidget(splitter);

        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 800, 21));
        menu = new QMenu(menubar);
        menu->setObjectName("menu");
        menu_2 = new QMenu(menubar);
        menu_2->setObjectName("menu_2");
        MainWindow->setMenuBar(menubar);
        statusBar = new QStatusBar(MainWindow);
        statusBar->setObjectName("statusBar");
        MainWindow->setStatusBar(statusBar);

        menubar->addAction(menu->menuAction());
        menubar->addAction(menu_2->menuAction());
        menu->addAction(actionExit);
        menu_2->addAction(actionAbout);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "\320\241\320\270\321\201\321\202\320\265\320\274\320\260 \320\276\320\261\320\275\320\260\321\200\321\203\320\266\320\265\320\275\320\270\321\217 \320\262\321\202\320\276\321\200\320\266\320\265\320\275\320\270\320\271 (IDS)", nullptr));
        actionExit->setText(QCoreApplication::translate("MainWindow", "\320\222\321\213\321\205\320\276\320\264", nullptr));
        actionAbout->setText(QCoreApplication::translate("MainWindow", "\320\236 \320\277\321\200\320\276\320\263\321\200\320\260\320\274\320\274\320\265", nullptr));
        label->setText(QCoreApplication::translate("MainWindow", "\320\241\320\265\321\202\320\265\320\262\320\276\320\271 \320\270\320\275\321\202\320\265\321\200\321\204\320\265\320\271\321\201:", nullptr));
        pushButtonStart->setText(QCoreApplication::translate("MainWindow", "\320\227\320\260\320\277\321\203\321\201\321\202\320\270\321\202\321\214", nullptr));
        pushButtonStop->setText(QCoreApplication::translate("MainWindow", "\320\236\321\201\321\202\320\260\320\275\320\276\320\262\320\270\321\202\321\214", nullptr));
        pushButtonClear->setText(QCoreApplication::translate("MainWindow", "\320\236\321\207\320\270\321\201\321\202\320\270\321\202\321\214", nullptr));
        groupBox->setTitle(QCoreApplication::translate("MainWindow", "\320\237\320\276\320\264\320\276\320\267\321\200\320\270\321\202\320\265\320\273\321\214\320\275\321\213\320\265 IP-\320\260\320\264\321\200\320\265\321\201\320\260", nullptr));
        groupBox_2->setTitle(QCoreApplication::translate("MainWindow", "\320\226\321\203\321\200\320\275\320\260\320\273 \321\201\320\276\320\261\321\213\321\202\320\270\320\271", nullptr));
        menu->setTitle(QCoreApplication::translate("MainWindow", "\320\244\320\260\320\271\320\273", nullptr));
        menu_2->setTitle(QCoreApplication::translate("MainWindow", "\320\241\320\277\321\200\320\260\320\262\320\272\320\260", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
