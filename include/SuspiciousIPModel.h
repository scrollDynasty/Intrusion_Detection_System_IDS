#ifndef SUSPICIOUSIPMODEL_H
#define SUSPICIOUSIPMODEL_H

#include <QAbstractTableModel>
#include <QVector>
#include <QMap>
#include <QString>
#include <QDateTime>

struct IPRecord {
    QString sourceIP;
    QString destinationIP;
    QString packetType;
    QDateTime timestamp;
    int count;
};

class SuspiciousIPModel : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit SuspiciousIPModel(QObject *parent = nullptr);

    // Обязательные методы QAbstractTableModel
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    // Метод для добавления записи о подозрительном IP
    void addSuspiciousIP(const QString& sourceIP, const QString& destinationIP, const QString& packetType, const QString& timestamp);

    // Метод для очистки всех записей
    void clearRecords();

private:
    QVector<IPRecord> records;
    QMap<QString, int> ipIndexMap; // Карта для быстрого поиска IP в records
};

#endif // SUSPICIOUSIPMODEL_H 