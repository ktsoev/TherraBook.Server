-- SQL команды для изменения схемы таблицы withdrawals
-- Добавление полей amount (денежная сумма) и stars_amount (количество звезд)

-- Шаг 1: Переименовываем существующее поле amount в stars_amount
ALTER TABLE `withdrawals` 
CHANGE COLUMN `amount` `stars_amount` INT NOT NULL;

-- Шаг 2: Добавляем новое поле amount для денежной суммы в долларах
ALTER TABLE `withdrawals` 
ADD COLUMN `amount` DECIMAL(10, 2) NULL DEFAULT NULL AFTER `stars_amount`;
