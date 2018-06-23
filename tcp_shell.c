/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 SummerGift <SummerGift@qq.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <rtthread.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <rtthread.h>
#include <lwip/sockets.h>
#include <lwip/netifapi.h>
#include <lwip/sockets.h>
#include <rtdevice.h>
#include <finsh.h>
#include <shell.h>

#if !defined(LWIP_NETIF_LOOPBACK) || (LWIP_NETIF_LOOPBACK == 0)
#error "must enable (LWIP_NETIF_LOOPBACK = 1) for publish!"
#endif /* LWIP_NETIF_LOOPBACK */

#define  debug_printf  rt_kprintf("[TCP_SHELL] ");rt_kprintf
//#define  debug_printf(...)

#define SOCK_TARGET_HOST "192.168.10.110"
#define SOCK_TARGET_PORT 6000
#define SHELL_UDP_PORT   7001
#define RX_BUFFER_SIZE   512
#define TX_BUFFER_SIZE   512
#define RT_CONSOLE_TCPSHELL_DEVICE_NAME "tcpshell"
#define MAX(x,y) ((x)<(y)?(y):(x))

rt_uint8_t g_count;
rt_uint8_t g_tcpshell_start_times;
static struct rt_tcpshell_session* g_tcpshell;
static const char send_data[] = "This is a TCP Client from RT-Thread.";

struct rt_tcpshell_session
{
    struct rt_device device;
    const char *host;
    
    struct rt_ringbuffer rx_ringbuffer;
    struct rt_ringbuffer tx_ringbuffer;
    
    rt_mutex_t rx_ringbuffer_lock;
    rt_mutex_t tx_ringbuffer_lock;
    
    /* client  sock */
    int sock;   
    int port;

    /* publish sock */
    int pub_sock;
    int pub_port;
    
    rt_uint8_t echo_mode;
};

int tcpshell_local_send(struct rt_tcpshell_session* tcpshell, const void *data, int len)
{
    struct sockaddr_in server_addr = {0};
    rt_uint8_t send_len;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(tcpshell->pub_port);
    server_addr.sin_addr = *((const struct in_addr *)&netif_default->ip_addr);
    memset(&(server_addr.sin_zero), 0, sizeof(server_addr.sin_zero));
    send_len = sendto(tcpshell->pub_sock, data, len, MSG_DONTWAIT,
              (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
    return send_len;
}

/* process tx data */                                                                  
static void send_to_tcpshell_client(struct rt_tcpshell_session* tcpshell)
{
    rt_size_t length;
    rt_uint8_t tx_buffer[128];

    while (1)
    {
        rt_memset(tx_buffer, 0, sizeof(tx_buffer));
        rt_mutex_take(tcpshell->tx_ringbuffer_lock, RT_WAITING_FOREVER);
        /* get buffer from ringbuffer */
        length = rt_ringbuffer_get(&(tcpshell->tx_ringbuffer), tx_buffer, sizeof(tx_buffer));
        rt_mutex_release(tcpshell->tx_ringbuffer_lock);

        /* do a tx procedure */ 
        if (length > 0)
        {
            tcpshell_local_send(g_tcpshell, tx_buffer, length);
        }
        else break;
    }
}

/* process rx data */
static void tcpshell_process_rx(struct rt_tcpshell_session* tcpshell, rt_uint8_t *data, rt_size_t length)
{
    rt_size_t rx_length, index;

    for (index = 0; index < length; index ++)
    {
         rt_mutex_take(tcpshell->rx_ringbuffer_lock, RT_WAITING_FOREVER);
         /* put buffer to ringbuffer */
         rt_ringbuffer_putchar(&(tcpshell->rx_ringbuffer), *data);
         rt_mutex_release(tcpshell->rx_ringbuffer_lock);    
         data ++;
    }

    rt_mutex_take(tcpshell->rx_ringbuffer_lock, RT_WAITING_FOREVER);
    /* get total size */
    rx_length = rt_ringbuffer_data_len(&tcpshell->rx_ringbuffer);
    rt_mutex_release(tcpshell->rx_ringbuffer_lock);

    /* indicate there are reception data */
    if ((rx_length > 0) && (tcpshell->device.rx_indicate != RT_NULL))
        tcpshell->device.rx_indicate(&tcpshell->device, rx_length);
    
    return;
}

/* client close */
static void client_close(struct rt_tcpshell_session* tcpshell)
{    
    /* set console */
    rt_console_set_device(RT_CONSOLE_DEVICE_NAME);
    /* set finsh device */
    finsh_set_device(RT_CONSOLE_DEVICE_NAME);

    /* restore shell option */
    tcpshell->echo_mode = 1;                //open echo
    finsh_set_echo(tcpshell->echo_mode);    
                      
    /* close connection */
    closesocket(tcpshell->sock);            //close tcp socket
    closesocket(tcpshell->pub_sock);        //close udp socket
    
    rt_kprintf("resume console to %s\n", RT_CONSOLE_DEVICE_NAME);
}

/* RT-Thread Device Driver Interface */
static rt_err_t tcpshell_init(rt_device_t dev)
{
    return RT_EOK;
}

static rt_err_t tcpshell_open(rt_device_t dev, rt_uint16_t oflag)
{
    return RT_EOK;
}

static rt_err_t tcpshell_close(rt_device_t dev)
{
    return RT_EOK;
}

static rt_size_t tcpshell_read(rt_device_t dev, rt_off_t pos, void* buffer, rt_size_t size)
{
    rt_size_t result;
    /* read from rx ring buffer */
    rt_mutex_take(g_tcpshell->rx_ringbuffer_lock, RT_WAITING_FOREVER);
    result = rt_ringbuffer_get(&(g_tcpshell->rx_ringbuffer), buffer, size);
    rt_mutex_release(g_tcpshell->rx_ringbuffer_lock);
    
    return result;
}

static rt_size_t tcpshell_write (rt_device_t dev, rt_off_t pos, const void* buffer, rt_size_t size)
{
    const rt_uint8_t *ptr;

    ptr = (rt_uint8_t*) buffer;

    rt_mutex_take(g_tcpshell->tx_ringbuffer_lock, RT_WAITING_FOREVER);
    while (size)
    {
        if (*ptr == '\n')
            rt_ringbuffer_putchar(&g_tcpshell->tx_ringbuffer, '\r');

        if (rt_ringbuffer_putchar(&g_tcpshell->tx_ringbuffer, *ptr) == 0) /* overflow */
            break;
        ptr++;
        size--;
    }
    rt_mutex_release(g_tcpshell->tx_ringbuffer_lock);

    /* send data to tcp server */
    send_to_tcpshell_client(g_tcpshell);

    return (rt_uint32_t) ptr - (rt_uint32_t) buffer;
}

static rt_err_t tcpshell_control(rt_device_t dev, int cmd, void *args)
{
    return RT_EOK;
}

#define BUFSZ   1024
#define SENDTO_BUF_LEN 64   
static void tcp_shell_entry(void* parameter)
{
    struct rt_tcpshell_session *tcp_shell =  g_tcpshell;                                       
    int rc = -1;
    size_t len = 0;
    int ret;
    char *recv_data;
    int  bytes_received;
    struct sockaddr_in server_addr;
    rt_uint8_t sendto_buf[SENDTO_BUF_LEN];
       
    struct timeval timeout_t;
    timeout_t.tv_sec = 1;
    timeout_t.tv_usec = 0;
    
    recv_data = rt_malloc(BUFSZ);
    if (recv_data == RT_NULL)
    {
        rt_kprintf("No memory\n");
        return;
    }
       
    if(!g_tcpshell_start_times)
    {    
        /* register telnet device */
        g_tcpshell->device.type     = RT_Device_Class_Char;
        g_tcpshell->device.init     = tcpshell_init;
        g_tcpshell->device.open     = tcpshell_open;
        g_tcpshell->device.close    = tcpshell_close;
        g_tcpshell->device.read     = tcpshell_read;
        g_tcpshell->device.write    = tcpshell_write;
        g_tcpshell->device.control  = tcpshell_control;

        /* no private */
        g_tcpshell->device.user_data = RT_NULL;

        /* register tcpshell device */
        rt_device_register(&g_tcpshell->device, RT_CONSOLE_TCPSHELL_DEVICE_NAME,
                         RT_DEVICE_FLAG_RDWR | RT_DEVICE_FLAG_STREAM);
    }
    
    struct sockaddr_in pub_server_addr; 
    memset(&pub_server_addr,0,sizeof(struct sockaddr_in));                              
    tcp_shell->pub_port = SHELL_UDP_PORT;
    pub_server_addr.sin_len = sizeof(pub_server_addr);
    pub_server_addr.sin_family = AF_INET;
    pub_server_addr.sin_port = htons((tcp_shell->pub_port));
    pub_server_addr.sin_addr.s_addr = INADDR_ANY;
                
_udpsocket:     
    if ((tcp_shell->pub_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)           
    {
        rt_kprintf("Socket error\n");
        return;
    }
    
    rc = bind(tcp_shell->pub_sock, (struct sockaddr *)&pub_server_addr, sizeof(struct sockaddr_in));      /* bind publish socket. */
        
_connect:   
    if ((tcp_shell->sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        rt_kprintf("Socket error\n");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SOCK_TARGET_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SOCK_TARGET_HOST);
    rt_memset(&(server_addr.sin_zero), 0, sizeof(server_addr.sin_zero));

    if (connect(tcp_shell->sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        rt_kprintf("Connect fail!\n");
        lwip_close(tcp_shell->sock);
        return;
    }

    debug_printf("tcp shell socket connected.\n");  
        
    ret = lwip_send(tcp_shell->sock,send_data,sizeof(send_data), 0);
    if (ret < 0)
    {
        lwip_close(tcp_shell->sock);
        rt_kprintf("\nsend error,close the socket.\r\n");
        goto _connect;
    }else if (ret == 0)
    {
        rt_kprintf("\n Send warning,send function return 0.\r\n");
    }
          
    /* set console */                                            // set console to tcpshell
    rt_console_set_device(RT_CONSOLE_TCPSHELL_DEVICE_NAME);
    /* set finsh device */
    finsh_set_device(RT_CONSOLE_TCPSHELL_DEVICE_NAME);
    g_tcpshell->echo_mode = finsh_get_echo();
    /* disable echo mode */
    g_tcpshell->echo_mode = 0;                                  // close echo
    finsh_set_echo(g_tcpshell->echo_mode);  
    
    fd_set readset;                                             // initialize fd_set list for select
    int maxfd;
    
    while(1)
    {       
        FD_ZERO(&readset);
        FD_SET(tcp_shell->sock, &readset);
        FD_SET(tcp_shell->pub_sock, &readset);
        maxfd = MAX(tcp_shell->sock,tcp_shell->pub_sock);
                    
        rc = lwip_select(maxfd + 1,&readset, RT_NULL, RT_NULL, &timeout_t);
        if(0 == rc) continue;
        
        if (FD_ISSET(tcp_shell->sock, &readset))
        {
            rt_memset(recv_data, 0, sizeof(recv_data));
            
            bytes_received = recv(tcp_shell->sock, recv_data, BUFSZ - 1, 0);
            if (bytes_received < 0)
            {
                lwip_close(tcp_shell->sock);  
                rt_kprintf("\nreceived error,close the socket.\r\n");
                goto _connect;                                
            }
            else if (bytes_received == 0)
            {           
                rt_kprintf("\ntcp disconnected.\r\n");
                client_close(tcp_shell);                        
                rt_free(recv_data);
                break;                                
            }
            tcpshell_process_rx(g_tcpshell, (rt_uint8_t *)recv_data, bytes_received);           
         }
        
        if (FD_ISSET(tcp_shell->pub_sock, &readset))
        {
            struct sockaddr_in pub_client_addr;
            uint32_t addr_len = sizeof(struct sockaddr);            
            len = recvfrom(tcp_shell->pub_sock, sendto_buf, SENDTO_BUF_LEN, MSG_DONTWAIT,
                             (struct sockaddr *)&pub_client_addr, &addr_len);   
            
            rc = lwip_send(tcp_shell->sock, sendto_buf, len,0);                      
            if (ret < 0)
            {
                lwip_close(tcp_shell->sock);
                rt_kprintf("\nsend error,close the socket.\r\n");
                goto _connect;
            }
            else if (ret == 0)
            {
                rt_kprintf("\n Send warning,send function return 0.\r\n");
            }                           
        }   
    }
    
_exit:
    return;
}

rt_uint8_t sendtoserver(void)
{
    rt_uint8_t len;
    char buf[64];   
    len = sprintf(buf,"today is a sunny day. %d\n",g_count);     
    tcpshell_local_send(g_tcpshell,buf, len);   
    g_count++;
    memset(buf,0,sizeof(buf));
    return 0;
}
FINSH_FUNCTION_EXPORT(sendtoserver, sendtoserver);

/*
 * This function initializes tcp_shell
 */
void tcpshell_start(void)
{   
    if (g_tcpshell == RT_NULL)
    {
        rt_uint8_t *ptr;

        g_tcpshell = rt_malloc(sizeof(struct rt_tcpshell_session));
        if (g_tcpshell == RT_NULL)
        {
            rt_kprintf("tcpshell: no memory\n");
            return;
        }
        /* init ringbuffer */
        ptr = rt_malloc(RX_BUFFER_SIZE);
        if (ptr)
        {
            rt_ringbuffer_init(&g_tcpshell->rx_ringbuffer, ptr, RX_BUFFER_SIZE);
        }
        else
        {
            rt_kprintf("tcpshell: no memory\n");
            return;
        }
        ptr = rt_malloc(TX_BUFFER_SIZE);
        if (ptr)
        {
            rt_ringbuffer_init(&g_tcpshell->tx_ringbuffer, ptr, TX_BUFFER_SIZE);
        }
        else
        {
            rt_kprintf("tcpshell: no memory\n");
            return;
        }
        /* create tx ringbuffer lock */
        g_tcpshell->tx_ringbuffer_lock = rt_mutex_create("tcpshellx", RT_IPC_FLAG_FIFO);
        /* create rx ringbuffer lock */
        g_tcpshell->rx_ringbuffer_lock = rt_mutex_create("tcpshell_rx", RT_IPC_FLAG_FIFO);
        
        g_tcpshell_start_times = 0;  //mark as first time start up
        
        rt_thread_t tid;
        tid = rt_thread_create("tcpshell",
                           tcp_shell_entry, RT_NULL,
                           2048, RT_THREAD_PRIORITY_MAX / 3 - 1, 5);
        if (tid != RT_NULL)
            rt_thread_startup(tid);     
    }
    else
    {
        g_tcpshell_start_times = 1; //not first time start up
        rt_kprintf("tcpshell: start up again.\n");
        rt_thread_t tid;
        tid = rt_thread_create("tcpshell",
                           tcp_shell_entry, RT_NULL,
                           2048, RT_THREAD_PRIORITY_MAX / 3 - 1, 5);
        if (tid != RT_NULL)
            rt_thread_startup(tid); 
    }
}
    
#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(tcpshell_start, startup tcpshell);
#ifdef FINSH_USING_MSH
MSH_CMD_EXPORT(tcpshell_start, startup tcpshell)
#endif /* FINSH_USING_MSH */
#endif /* RT_USING_FINSH */