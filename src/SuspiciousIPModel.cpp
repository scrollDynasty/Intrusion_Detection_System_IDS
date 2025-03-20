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
            return QBrush(QColor(255, 80, 80, 255));
        } else if (record.count > 10) {
            // Высокий уровень - оранжевый
            return QBrush(QColor(255, 150, 0, 255));
        } else if (record.count > 5) {
            // Средний уровень - желтый
            return QBrush(QColor(255, 255, 0, 255));
        } else {
            // Низкий уровень - светло-желтый
            return QBrush(QColor(255, 255, 200, 255));
        }
    } else if (role == Qt::ForegroundRole) {
        // Цвет текста для лучшей читаемости - ВСЕГДА используем черный цвет,
        // чтобы на всех фонах было хорошо видно
        return QBrush(QColor(0, 0, 0));
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
        QString severityColor;
        
        if (record.count > 20) {
            severity = "Критический";
            severityColor = "#FF0000"; // Красный
        } else if (record.count > 10) {
            severity = "Высокий";
            severityColor = "#FF9900"; // Оранжевый
        } else if (record.count > 5) {
            severity = "Средний";
            severityColor = "#FFCC00"; // Желтый
        } else {
            severity = "Низкий";
            severityColor = "#66CC66"; // Зеленый
        }
        
        // Создаем форматированную строку с HTML для лучшего отображения
        return QString(
            "<html>"
            "<head>"
            "<style>"
            "table { border-collapse: collapse; width: 100%; }"
            "th, td { padding: 4px; text-align: left; }"
            "th { background-color: #666; color: white; }"
            "td { border-bottom: 1px solid #ddd; }"
            "</style>"
            "</head>"
            "<body style='background-color: #f8f8f8; color: #333;'>"
            "<h3 style='margin: 0 0 10px 0;'>Информация о подозрительном IP</h3>"
            "<table>"
            "<tr><th>Параметр</th><th>Значение</th></tr>"
            "<tr><td>Источник:</td><td>%1</td></tr>"
            "<tr><td>Назначение:</td><td>%2</td></tr>"
            "<tr><td>Тип пакета:</td><td>%3</td></tr>"
            "<tr><td>Время:</td><td>%4</td></tr>"
            "<tr><td>Количество пакетов:</td><td>%5</td></tr>"
            "<tr><td>Уровень угрозы:</td><td><span style='font-weight: bold; color: %6;'>%7</span></td></tr>"
            "</table>"
            "</body>"
            "</html>"
        )
        .arg(record.sourceIP)
        .arg(record.destinationIP)
        .arg(record.packetType)
        .arg(record.timestamp.toString("yyyy-MM-dd hh:mm:ss"))
        .arg(record.count)
        .arg(severityColor)
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
    
    // Всегда обновляем запись, даже если она уже существует
    // Проверяем, есть ли уже такая запись
    if (ipIndexMap.contains(key)) {
        int row = ipIndexMap[key];
        records[row].count++;
        records[row].timestamp = QDateTime::currentDateTime();
        records[row].packetType = packetType; // Обновляем также тип пакета
        // Обновляем больше ячеек, чтобы строка полностью перерисовалась
        emit dataChanged(index(row, 0), index(row, 4));
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