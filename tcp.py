import asyncio
from random import randint
from grader.tcputils import *


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, window_size)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))
            
    def remover_conexao(self, id_conexao):
        self.conexoes.pop(id_conexao, None)

class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, window_size):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.current_window_size = window_size
        self.current_seq_no = randint(0, 0xffff)
        self.expected_seq_no = seq_no + 1
        self.prestes_a_fechar = False

        # Responde com SYNACK para a abertura de conexão
        self.enviar_segmento(
            self.current_seq_no,
            self.expected_seq_no,
            FLAGS_SYN | FLAGS_ACK,
            b'',
        )
        self.current_seq_no += 1

        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        print('recebido payload: %r' % payload)

        # ACK do fechamento
        if self.prestes_a_fechar:
            self.servidor.remover_conexao(self.id_conexao)
            return

        # Fechamento de conexão
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.expected_seq_no += 1
            self.enviar_segmento(
                self.current_seq_no,
                self.expected_seq_no,
                FLAGS_ACK,
                b''
            )
            self.callback(self, b'')
            return


        # Apenas um ACK
        if (flags & FLAGS_ACK) == FLAGS_ACK and len(payload) == 0:
            return

        if seq_no == self.expected_seq_no:
            self.expected_seq_no += len(payload)
            self.callback(self, payload)

        self.enviar_segmento(
            self.current_seq_no,
            self.expected_seq_no,
            FLAGS_ACK,
            b'',
        )

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """

        while len(dados) > MSS:
            print(f'{len(dados)} / {MSS}')
            self.enviar_segmento(
                self.current_seq_no,
                self.expected_seq_no,
                FLAGS_ACK,
                dados[:MSS]
            )
            self.current_seq_no += MSS
            dados = dados[MSS:]

        print(f'{len(dados)} / {MSS}')
        self.enviar_segmento(
            self.current_seq_no,
            self.expected_seq_no,
            FLAGS_ACK,
            dados
        )
        self.current_seq_no += len(dados)

    def enviar_segmento(self, seq_no, ack_no, flags, payload):
        segment = make_header(
            self.id_conexao[3],
            self.id_conexao[1],
            seq_no,
            ack_no,
            flags,
        )
        segment = segment + payload
        segment = fix_checksum(
            segment,
            self.id_conexao[2],
            self.id_conexao[0]
        )

        self.servidor.rede.enviar(segment, self.id_conexao[0])

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        self.prestes_a_fechar = True
        self.enviar_segmento(
            self.current_seq_no,
            self.expected_seq_no,
            FLAGS_FIN,
            b'',
        )
