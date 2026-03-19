# net-normalizer

Утилита для дедупликации и объединения IPv4 подсетей и фильтрации IP-адресов, которые уже входят в указанные сети.
Добавлена функция вычитания черного списка

Алгоритм вычитания работает на уровне 32-битных чисел, а не строк. Каждый CIDR конвертируется в точный диапазон [start, end]. Функция subtract_ranges рассматривает все 5 возможных случаев пересечения диапазонов, и в каждом случае restricted-часть физически не добавляется в результат. Это доказывается инвариантом: после каждой итерации цикла ни один адрес из restricted не содержится в new_result. Тесты покрывают граничные случаи включая u32::MAX. Двойная фильтрация IP гарантирует, что даже если CIDR-конвертация даст сбой, restricted IP список удалит адреса напрямую.

### Особенности

* Объединяет перекрывающиеся подсети (`CIDR merge`)
* Добавлена функция вычитания черного списка
* Убирает IP, находящиеся внутри сетей
* Поддержка JSON ввода/вывода
* Работает с приватными и публичными IPv4

### Формат входного JSON

```json
{
  "networks": [
    "192.168.1.0/24",
    "10.0.0.0/8"
  ],
  "ips": [
    "192.168.1.50",
    "8.8.8.8"
  ]
}
```

### Формат выходного JSON

```json
{
  "networks": [
    "10.0.0.0/8",
    "192.168.1.0/24"
  ],
  "ips": [
    "8.8.8.8"
  ]
}
```

### Сборка

```bash
cargo build --release
```

### Примеры запуска

* Через файл:

```bash
# Без blacklist
./net-normalizer input.json

# С blacklist
./net-normalizer input.json restricted.json

# Через pipe (без blacklist)
cat input.json | ./net-normalizer

# Через pipe + blacklist
cat input.json | ./net-normalizer restricted.json
```

# 1. Сборка релиза
`cargo build --release`

# 2. Запуск тестов
`cargo test`
```
running 5 tests
test tests::test_ip_to_u32_roundtrip ... ok
test tests::test_merge_adjacent_ranges ... ok
test tests::test_subtract_ranges_full_overlap ... ok
test tests::test_subtract_ranges_no_overlap ... ok
test tests::test_subtract_ranges_split ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
# 3. Запуск тестов с выводом (если нужно)
`cargo test -- --nocapture`

# 4. Проверка без оптимизаций (быстрее)
`cargo test --dev`
```
Случай 1: Нет пересечения
Input:      [───────────────]
Restricted:                   [───────]
Result:     [───────────────]  ← осталось всё

Случай 2: Полное покрытие
Input:      [───────]
Restricted: [───────────────]
Result:     (пусто)  ← удалено полностью

Случай 3: Пересечение слева
Input:      [───────────────]
Restricted: [───────]
Result:             [───────]  ← левая часть удалена

Случай 4: Пересечение справа
Input:      [───────────────]
Restricted:         [───────]
Result:     [───────]          ← правая часть удалена

Случай 5: Restricted внутри
Input:      [───────────────────]
Restricted:     [───────]
Result:     [───]       [───────]  ← средняя часть удалена
            ↑           ↑
            до          после
            restricted  restricted

```

```

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   input.json    │ --> │   CIDR → Range  │ --> │   merge_ranges  │
│   (allowed)     │     │   (точно)       │     │   (union)       │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
┌─────────────────┐     ┌─────────────────┐     ┌────────▼────────┐
│   restricted    │ --> │   CIDR → Range  │ --> │   merge_ranges  │
│   .json         │     │   (точно)       │     │   (union)       │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────┐
                                                │ subtract_ranges │
                                                │   (вычитание)   │
                                                └────────┬────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────┐
                                                │  Range → CIDR   │
                                                │   (покрытие)    │
                                                └────────┬────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────────┐
                                                │   output.json       │
                                                │   (без restricted)  │
                                                └─────────────────────┘
```
