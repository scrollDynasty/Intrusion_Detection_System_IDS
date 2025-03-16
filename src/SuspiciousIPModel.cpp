#include "SuspiciousIPModel.h"
#include <QColor>
#include <QBrush>
#include <QFont>

SuspiciousIPModel::SuspiciousIPModel(QObject *parent)
    : QAbstractTableModel(parent) {
}

int SuspiciousIPModel::rowCount(const QModelIndex &parent) const {
    if (parent.isValid())
        return 0;
    return records.size();
}

int SuspiciousIPModel::columnCount(const QModelIndex &parent) const {
    if (parent.isValid())
        return 0;
    return 5; // IP источника, IP назначения, тип пакета, время, количество
}

QVariant SuspiciousIPModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= records.size())
        return QVariant();

    const IPRecord &record = records.at(index.row());

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case 0: return record.sourceIP;
            case 1: return record.destinationIP;
            case 2: return record.packetType;
            case 3: return record.timestamp.toString("yyyy-MM-dd hh:mm:ss");
            case 4: return record.count;
            default: return QVariant();
        }
    } else if (role == Qt::BackgroundRole) {
        // Улучшенное выделение записей в зависимости от количества пакетов
        if (record.count > 20) {
            // Критический уровень - яркий красный
            return QBrush(QColor(255, 100, 100, 200));
        } else if (record.count > 10) {
            // Высокий уровень - оранжевый
            return QBrush(QColor(255, 165, 0, 180));
        } else if (record.count > 5) {
            // Средний уровень - желтый
            return QBrush(QColor(255, 255, 0, 150));
        }
    } else if (role == Qt::ForegroundRole) {
        // Цвет текста для лучшей читаемости
        if (record.count > 20) {
            return QBrush(QColor(255, 255, 255)); // Белый текст на красном фоне
        } else if (record.count > 10) {
            return QBrush(QColor(0, 0, 0)); // Черный текст на оранжевом фоне
        }
    } else if (role == Qt::FontRole) {
        QFont font;
        if (record.count > 20) {
            font.setBold(true);
            font.setPointSize(10); // Увеличиваем размер шрифта
            return font;
        } else if (record.count > 10) {
            font.setBold(true);
            return font;
        }
    } else if (role == Qt::ToolTipRole) {
        // Добавляем всплывающую подсказку с дополнительной информацией
        QString severity;
        if (record.count > 20) {
            severity = "Критический";
        } else if (record.count > 10) {
            severity = "Высокий";
        } else if (record.count > 5) {
            severity = "Средний";
        } else {
            severity = "Низкий";
        }
        
        return QString("Источник: %1\nНазначение: %2\nТип: %3\nВремя: %4\nКоличество: %5\nУровень угрозы: %6")
                .arg(record.sourceIP)
                .arg(record.destinationIP)
                .arg(record.packetType)
                .arg(record.timestamp.toString("yyyy-MM-dd hh:mm:ss"))
                .arg(record.count)
                .arg(severity);
    }

    return QVariant();
}

QVariant SuspiciousIPModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return QVariant();

    switch (section) {
        case 0: return tr("IP источника");
        case 1: return tr("IP назначения");
        case 2: return tr("Тип пакета");
        case 3: return tr("Время");
        case 4: return tr("Количество");
        default: return QVariant();
    }
}

void SuspiciousIPModel::addSuspiciousIP(const QString& sourceIP, const QString& destinationIP, const QString& packetType, const QString& timestamp) {
    // Создаем ключ для поиска в карте
    QString key = sourceIP + "->" + destinationIP;
    
    // Проверяем, есть ли уже такая запись
    if (ipIndexMap.contains(key)) {
        int row = ipIndexMap[key];
        records[row].count++;
        records[row].timestamp = QDateTime::currentDateTime();
        emit dataChanged(index(row, 3), index(row, 4));
    } else {
        // Добавляем новую запись
        beginInsertRows(QModelIndex(), records.size(), records.size());
        
        IPRecord record;
        record.sourceIP = sourceIP;
        record.destinationIP = destinationIP;
        record.packetType = packetType;
        record.timestamp = QDateTime::fromString(timestamp, "yyyy-MM-dd hh:mm:ss");
        if (!record.timestamp.isValid()) {
            record.timestamp = QDateTime::currentDateTime();
        }
        record.count = 1;
        
        ipIndexMap[key] = records.size();
        records.append(record);
        
        endInsertRows();
    }
}

void SuspiciousIPModel::clearRecords() {
    beginResetModel();
    records.clear();
    ipIndexMap.clear();
    endResetModel();
} 