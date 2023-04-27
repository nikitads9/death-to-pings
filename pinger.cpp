#include <arpa/inet.h> //definitions for internet operations

#include <sys/types.h> //The data types

#include <sys/param.h> //Сдесь хранятся константы

#include <sys/socket.h> //Fot Internet Protocol

#include <sys/stat.h> //data returned

#include <sys/time.h> //The time types

#include <netinet/in_systm.h> //The Internet address family in sys

#include <netinet/in.h> //The Internet address family

#include <netinet/ip_icmp.h> //For ICMP

#include <netdb.h> //for network database operations

#include <unistd.h> //standard symbolic constants and types

#include <stdio.h> //standard input/output header

#include <ctype.h> //Character handling functions

#include <ctime> //Getting the date and time

#include <cstring> //for string

#include <fcntl.h> //Creating or overwriting a file

#include <string.h> //for string

#include <sstream> //providing string stream classes

#include <fstream> // To write to a file

#include <errno.h> // To work with error numbers

#include <stdlib.h> //for memory allocation routines

#include <stdint.h> //header defines integer types

#include <iostream> //standard input/output header

#define DEBUG(MS) printf(MS) // debug

#define MAX_PACKET 1024 // Размер буфера для приходящего пакета

#define ICMP_SIZE 64 // Размер посылаемого пакета

#define MaxSize 2000000 // Размер файла лога после которого он будет считаться переполненным

#define REQUEST_NUMBER 10

// Функции программы

int createLogFile(); // Создание лог файла

int checkParams(int); // Проверка колличестов входных аргументов

int assembling(); // Сборка пакета

int sendRequest(); // Отправка пакета

int recvResponse(); // Прием пакета

// Функции лога

int isLogExist(); // Для проверки существования или переполненности лога

int createLog(); // Создание лога

int PingDiag(int TypeError); // Вывод ошибок возникших в работе программы

int writeLogFile(std::string); // Запись сообщения в лог

void LogDiag(int); // Диагностика ошибок лога

struct sockaddr_in saServer, from; // Информация о сокете

std::string hostname; // Имя сервера

struct hostent *hp; // Информация о хосте

u_char *packet[MAX_PACKET], *recvbuf = NULL; // Для ICMP пакета один для отправки, другой для примема

struct icmp *icp; // Структура для icmp пакета

int sock; // переменная для сокета

struct timeval start, end; // Для фиксации времени

fd_set rfds; // добавляют заданный описатель к набору

struct timeval tv; // для select

struct ip *ip; // Структра ip

int no_data; // Для счета количество провалов

int req; // Переменная для цикла

char *username; // Переменная под имя пользователя

// char log_buff[128]; // Переменная под сборку пути к логу
char *log_buff; // Переменная под сборку пути к логу

bool Overflow; // Переменная показывающая не переполнен ли лог

int Errornum; // Переменная под хранение номера ошибки

struct stat logStat; // Создание структуры информации о файле

char *buff; // Буфер для формирования записи в лог

char *date; // Переменная для получения текущей даты

time_t now; // Структура для получения времени

// ======================================== КОНЕЦ ДЕКЛАРАЦИИ ПЕРЕМЕННЫХ, МАКРОСОВ И БИБЛИОТЕК ========================================

// ======================================== ДЕКЛАРАЦИИ ФУНКЦИЙ ========================================

int createLogFile()
{

  DEBUG("Create log\n");

  if (isLogExist() == 1)

  {

    int i = createLog();

    if (i == 1)
    {

      return 1;
    }

    return 0;
  }

  return 0;
}

int checkParams(int argc)
{ // Проверка количества входных аргументов

  DEBUG("Check enter arg\n");

  if (argc != 2)
  {

    printf("usage: ip/dns address\n");

    PingDiag(20);

    return 1;
  }

  return 0;
}

int createSock(char *argv[])
{

  // DEBUG("Check dns or ip\n");
  DEBUG("Check Ip\n");

  std::string target = argv[1]; // Меняем аргумент из char in str

  std::stringstream ss; // Для преоброзавние строки

  std::string strOut; // Для хранения преобразованной строки

  char hnamebuf[MAXHOSTNAMELEN]; // буфер для hostname

  saServer.sin_family = AF_INET; // Назначаем принадлежность к ipv4

  saServer.sin_addr.s_addr = inet_addr(target.c_str()); // Назначаем адрес

  if (saServer.sin_addr.s_addr != (u_int)-1) // Проверяем тип адреса

    hostname = target; // Если адрес ip то не меняем адрес

  // else // Если адрес DNS

  // {

  //   hp = gethostbyname(target.c_str()); // Ищем в базе ip входящего DNS

  //   if (!hp)

  //   {

  //     printf("Unkown host");

  //     PingDiag(30);

  //     return 1;
  //   }

  //   // Переопределяем тип и имя

  //   saServer.sin_family = hp->h_addrtype;

  //   bcopy(hp->h_addr, (caddr_t)&saServer.sin_addr, hp->h_length);

  //   strncpy(hnamebuf, hp->h_name, sizeof(hnamebuf) - 1);

  //   hostname = hnamebuf;
  // }

  ss << "Host IP: " << inet_ntoa(saServer.sin_addr) << std::endl;

  strOut = ss.str();

  printf(strOut.c_str());

  writeLogFile(strOut);

  return 0;
}

static uint16_t in_cksum(uint16_t *addr, unsigned len)

{

  DEBUG("Chek Summa\n");

  uint16_t answer = 0;

  /*

  * Algorithm is simple, using a 32 bit accumulator (sum), add

  * sequential 16 bit words to it, and at the end, fold back all the

  * carry bits from the t 16 bits into the lower 16 bits.

  */

  uint32_t sum = 0;

  while (len > 1)
  {

    sum += *addr++;

    len -= 2;
  }

  if (len == 1)
  {

    *(unsigned char *)&answer = *(unsigned char *)addr;

    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff);

  sum += (sum >> 16);

  answer = ~sum;

  return answer;
}

int assembling()
{ // Собираем пакет
  DEBUG("Assembling packet\n");

  if ((recvbuf = (u_char *)malloc((u_int)MAX_PACKET)) == NULL) // Создаем буфер для входящих пакетов

  {

    printf("malloc error\n");

    PingDiag(40);

    PingDiag(41);

    return 1;
  }

  if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) // Создаем сокет

  {

    printf("Needs to run as superuser!!\n ");

    PingDiag(40);

    PingDiag(42);

    return 1; /* Needs to run as superuser!! */
  }

  // Определям заголовок пакета

  icp = (struct icmp *)packet;

  icp->icmp_type = ICMP_ECHO; // Тип пакета

  icp->icmp_code = 0;

  icp->icmp_cksum = 0; // сумма пакета (изменется дальше)

  icp->icmp_seq = 12345; // последоваетльность

  icp->icmp_id = getpid(); // id пакета

  icp->icmp_cksum = in_cksum((unsigned short *)icp, ICMP_SIZE); // сума пакета

  FD_ZERO(&rfds);

  FD_SET(sock, &rfds);

  tv.tv_sec = 1;

  tv.tv_usec = 0;

  return 0;
  return 0;
}

int sendRequest()
{

  DEBUG("Request\n");

  sleep(1);

  gettimeofday(&start, NULL); // фиксация времени отправки

  // отправляем пакет и проверяем получилось ли

  int i = sendto(sock, (char *)packet, ICMP_SIZE, 0, (struct sockaddr *)&saServer, (socklen_t)sizeof(struct sockaddr_in));

  if (i < 0)
  {

    printf("sendto error");

    PingDiag(50);

    return 1;
  }

  return 0;
}

int recvResponse()
{

  DEBUG("Response\n");

  int fromlen, ret, hlen, end_t;

  std::stringstream ss; // Для преоброзавние строки

  std::string strOut; // Для хранения преобразованной строки

  // блокируемся пока не получим данные или не истечет время

  int retval = select(sock + 1, &rfds, NULL, NULL, &tv);

  if (retval == -1)

  {

    perror("select()");

    PingDiag(60);

    PingDiag(61);

    return 1;
  }

  else if (retval)

  {

    fromlen = sizeof(sockaddr_in);

    if ((ret = recvfrom(sock, (char *)recvbuf, MAX_PACKET, 0, (struct sockaddr *)&from, (socklen_t *)&fromlen)) < 0)

    {

      perror("recvfrom error");

      PingDiag(60);

      return 1;
    }

    // Check the IP header

    ip = (struct ip *)((char *)recvbuf);

    hlen = sizeof(struct ip);

    if (ret < (hlen + ICMP_MINLEN)) // Не соответсвие разменра пакета

    {

      std::cout << "packet too short ( " << ret << " bytes) from " << hostname << " hostname" << std::endl;

      PingDiag(60);

      PingDiag(62);

      return 1;
    }

    icp = (struct icmp *)(recvbuf + hlen);

    if (icp->icmp_type == ICMP_ECHOREPLY)

    {

      if (icp->icmp_seq != 12345) // не соответсвие последовательности

        printf("received sequence # %c \n", icp->icmp_seq);

      if (icp->icmp_id != getpid()) // не правильный id пакета

        printf("received id %c \n", icp->icmp_id);
    }

    else
    {

      printf("Recv: not an echo reply \n");

      PingDiag(60);

      return 1;
    }

    gettimeofday(&end, NULL); // фиксация время получения пакета

    end_t = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);

    if (end_t < 1)

      end_t = 1;

    ss << "Ping host: " << inet_ntoa(from.sin_addr)

       << " time = " << end_t << "usec " << std::endl;

    strOut = ss.str();

    printf(strOut.c_str());
    writeLogFile(strOut.c_str());

    return 0;
  }

  else

  {

    if (no_data == 5)
    {

      printf("No data about node.\n");

      PingDiag(60);

      PingDiag(63);

      return 1;
    }

    else
    {

      printf("No data within one seconds.\n");

      writeLogFile("No data within one seconds.\n");

      return 0;
    }
  }
}

int isLogExist() // Функция проверки наличия и переполнения лога

{

  username = getenv("USER"); // Получение имени пользователя

  // Сборка пути

  sprintf(log_buff, "%s%s%s", "/home/", username, "/Desktop/Ping/Ping_log.txt");

  if (stat((char *)log_buff, &logStat) == -1) // Заполнение структуры информации о файле

  {

    return 1; // Возвращаем 1 говоря что файла не существует
  }

  else if (logStat.st_size > MaxSize)

  {

    std::cout << "Файл лога переполнился и будет перезаписан";

    Overflow = true;

    return 1;
  }

  return 0; // Возвращаем 0 говоря что файла существует
}

int createLog() // Функция создания папки и лога

{

  char path_buff[128]; // Переменная под сборку команды

  int result; // Переменная под результат создания папки

  // Сборка команды создания директории

  sprintf(path_buff, "%s%s%s", "mkdir -p /home/", username, "/Desktop/Ping");

  result = system(path_buff); // Создание директории

  if (result == -1) // Обработка ошибки

  {

    LogDiag(10);

    return 1;
  }

  if (Overflow)

  {

    result = open((char *)log_buff, O_RDWR | O_TRUNC); // Перезапись файла лога
  }

  else

  {

    // Создание файла

    result = open((char *)log_buff, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  }

  if (result == -1) // Обработка ошибки

  {

    Errornum = errno;

    LogDiag(Errornum);

    LogDiag(11);

    return 1;
  }

  close(result);

  return 0;
}

int PingDiag(int TypeError) // Функция записи ошибки в лог

{

  switch (TypeError)

  {


  case 20:

  {

    writeLogFile("ERROR Неверное количество входных аргументов");

    break;
  }

  case 30:

  {

    writeLogFile("ERROR Доменное имя не соответствует никакому IP");

    break;
  }

  case 40:

  {

    writeLogFile("ERROR Пакет не собран");

    break;
  }

  case 41:

  {

    writeLogFile("ERROR malloc");

    break;
  }

  case 42:

  {

    writeLogFile("ERROR Недостаточно прав");

    break;
  }

  case 50:

  {

    writeLogFile("ERROR При отправке возникла ошибка");

    break;
  }

  case 60:

  {

    writeLogFile("ERROR Пакет не получен");

    break;
  }

  case 61:

  {

    writeLogFile("ERROR select()");

    break;
  }

  case 62:

  {

    writeLogFile("ERROR Не соответсвие разменра пакета ");

    break;
  }

  case 63:

  {

    writeLogFile("ERROR Нет данных о ноде");

    break;
  }
  }

  return 0;
}

void LogDiag(int TypeError)

{

  switch (TypeError) // Вывод сообщения в зависимости от значения errno

  {

  case 1:

  {

    std::cout << "Операция не разрешена";

    break;
  }

  case 10:

  {

    std::cout << "Ошибка создания директории для лога" << std::endl;

    break;
  }

  case 11:

  {

    std::cout << "Ошибка создания файла лога" << std::endl;

    break;
  }

  case 12:

  {

    std::cout << "Ошибка записи в лог" << std::endl;

    break;
  }

  case 19:

  {

    std::cout << "Не достаточно памяти";

    break;
  }

  case 13:

  {

    std::cout << "Доступ запрещен";

    break;
  }

  case 26:

  {

    std::cout << "Текстовый файл занят";

    break;
  }

  default:

  {

    std::cout << "Неопознанная ошибка код errno = " << TypeError;

    break;
  }
  }
}

int writeLogFile(std::string Message) // Функция добавления записи в лог

{
  char *Mess = new char[Message.length() + 1]; // Создание массива под содержимое сообщения

  strcpy(Mess, Message.c_str()); // Копирование сообщения в массив

  time(&now); // Заполняем структуру

  date = ctime(&now);

  date[strlen(date) - 1] = '\0';

  sprintf(buff, "[%s] %s", date, Mess); // Формирование записи в лог

  std::fstream fs;

  fs.open(log_buff, std::fstream::app); // Открытие файла

  if (!fs.is_open())

  {

    Errornum = errno;

    LogDiag(Errornum);

    LogDiag(12);

    return 1;
  }

  fs << buff << std::endl;

  fs.close();

  delete[] Mess; // Удаление массива

  return 0;
}

// ======================================== КОНЕЦ ДЕКЛАРАЦИИ ФУНКЦИЙ ========================================

// ======================================== ТЕЛО ПРОГРАММЫ ========================================

int main(int argc, char *argv[])

{

  setlocale(LC_ALL, "Russian");

  saServer = {0}; // Информация о сокете
  from = {0};     // Информация о сервере
  hostname = "";  // Имя сервера
  hp = NULL;      // Информация о хосте
  // packet = NULL; // Для ICMP пакета один для отправки, другой для примема
  recvbuf = NULL; // Для ICMP пакета один для отправки, другой для примема
  icp = {0};      // Структура для icmp пакета
  sock = 0;       // переменная для сокета
  start = {0};    // Для фиксации времени
  end = {0};      // Для фиксации времени
  // rfds = 0; // добавляют заданный описатель к набору
  tv = {0};    // для select
  ip = {0};    // Структра ip
  no_data = 0; // Для счета количество провалов
  req = 0;     // Переменная для цикла
  // username = "Q"; // Переменная под имя пользователя
  log_buff = new char[128]; // Переменная под сборку пути к логу
  Overflow = false;         // Переменная показывающая не переполнен ли лог
  Errornum = 0;             // Переменная под хранение номера ошибки
  buff = new char[128];     // Буфер для формирования записи в лог
  now = 0;                  // Структура для получения времени
  logStat = {};             // Для получения информации о файе
  date = NULL;              // Переменная для получения текущей даты
  switch (createLogFile())  // Создание лог файла
  {

  case 0:

    switch (checkParams(argc)) // Проверка колличестов входных аргументов

    {

    case 0:

      switch (createSock(argv)) // Check Ip address

      {

      case 0:
        switch (assembling()) // Сборка пакета [createSocket]

        {

        case 0:

          while (req <= REQUEST_NUMBER) // Вместо 10 вынести в константу

          {

            req++;

            switch (sendRequest()) // Отправка пакета

            {

            case 0:

              switch (recvResponse()) // Прием пакета

              {

              case 0: // убрать

                continue; // убрать

              case 1:

                printf("Error code = 60\n"); // нету ping diag, дописать

                return 60;

                break;
              }

            case 1:

              printf("Error code = 50\n"); // Тоже debug...

              return 50;

              break;
            }
          }

          break;

        case 1:

          printf("Error code = 40\n");

          return 40;

          break;
        }

        break;

      case 1:

        printf("Error code = 30\n");

        return 30;

        break;
      }

      break;

    case 1:

      printf("Error code = 20\n");

      return 20;

      break;
    }

    break;

  case 1:

    printf("Error code = 10\n");

    return 10;

    break;
  }
  return 0;
}

// ======================================== КОНЕЦ ТЕЛА ПРОГРАММЫ ========================================

/*

*/
