#include "time.h"
#include <time.h>
#include <string.h>

date_time current_datetime()
{
    date_time dt = {0};
	struct tm * time_info;
	time_t raw_time;
	time(&raw_time);
	time_info = localtime(&raw_time);
    // our date_time is the same as struct tm
    memmove(&dt, time_info, sizeof(*time_info));
    return dt;
}