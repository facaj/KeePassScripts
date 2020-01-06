# coding: utf-8
#!/usr/bin/python
from pykeepass import PyKeePass
from getpass import getpass
from paramiko import SSHClient
import paramiko
import logging
import time
from random import choice
from random import randint

class SSH:
    def __init__(self, IP, USUARIO, SENHA, PORTA):
        self.ip = IP
        self.ssh = SSHClient()
        self.ssh.load_system_host_keys()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
                self.ssh.connect(hostname=IP,username=USUARIO,password=SENHA,port=PORTA,timeout=3)
        except Exception as e:
                print str(e)

    def exec_cmd(self,cmd):
        stdin,stdout,stderr = self.ssh.exec_command(cmd,timeout=2)
        if stderr.channel.recv_exit_status() != 0:
            print stderr.read()
            return self.ip
        else:
            return stdout.read()


class AlteraKeePass:
        def __init__(self,arquivo_kdbx,senha):
                self.kp = PyKeePass(arquivo_kdbx, password=senha)

        def cria_entrada(self,grupo,nome,usuario,senha,url,icone,ip,porta):
                self.group = self.kp.find_groups(name=grupo, first=True)
                self.kp.add_entry(self.group, nome, usuario, senha,url=url,icon=icone)
                self.entry = self.kp.find_entries(title=nome, first=True)
                self.entry.set_custom_property('IP',ip)
                self.entry.set_custom_property('PORT',porta)
                self.kp.save()



if __name__ == '__main__':
        logging.basicConfig()
        paramiko_logger = logging.getLogger("paramiko.transport")
        paramiko_logger.disabled = True

        arq = open('/home/usuario/lista_ip.txt','r')
        lista = arq.readlines()


        def gera_novasenha(tamanho):
                caracters = '0123456789abcdefghijlmnopqrstuwvxzABCDEFGHIJKLMNOPQRSTUVXYZ@()&+_*-$'
                novasenha = ''
                for char in xrange(tamanho):
                        novasenha += choice(caracters)
                return  novasenha

        keepassfile = raw_inpur("Arquivo para adicionar (Ex: C:/arq.kdbx) ")
        keepasspass = getpass("Digite a senha do arquivo KeePass: ")
        usuario = raw_inpur("Usuario SSH: ")
        senha = getpass("Digite sua senha SSH: ")
        for linha in lista:
                ip = linha.split(",")[0]
                porta = linha.split(",")[1]
                print ip
                conectou=False
                try:
                        try:
                                ssh = SSH(ip,usuario,senha,int(porta))
                                conectou = True
                        except (paramiko.ssh_exception.AuthenticationException) as e:
                                conectou = False
                                print str(e)
                        if conectou:
                                nome = ssh.exec_cmd('hostname')
                                print nome
                                novasenha=gera_novasenha(randint(30,40))
                                print "IP: " + str(ip) + " nova senha: " + str(novasenha)
                                saida = ssh.exec_cmd('(echo "' + senha +'"  ;echo "' + novasenha +'" ; echo "' + novasenha +'") | passwd ')
                                print "Alteracao de senha, saida: " + str(saida)
                                keepass = AlteraKeePass(keepassfile,keepasspass)
                                keepass.cria_entrada('SSH',nome,usuario,novasenha,'kitty://','30',ip,porta)
                                ssh.close()
                except Exception as e:
                        print "Error :" + str(e)



