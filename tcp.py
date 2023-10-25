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
        self.timer = None
        self.unacked_segments = []
        self.current_window_size = window_size
        self.current_seq_no = randint(0, 0xffff)
        self.last_acked_no = self.current_seq_no
        self.expected_seq_no = seq_no + 1
        self.prestes_a_fechar = False

        # Responde com SYNACK para a abertura de conexão
        self.enviar_segmento(
            self.current_seq_no,
            self.expected_seq_no,
            FLAGS_SYN | FLAGS_ACK,
            b'',
        )

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        print('recebido payload: %r' % payload)

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

        # Um ACK
        if (flags & FLAGS_ACK) == FLAGS_ACK:
            if ack_no > self.last_acked_no:
                if self.timer is not None:
                    self.timer.cancel()
                    self.timer = None

                self.last_acked_no = ack_no
                smallest_unacked_segment_idx = None
                for i, (unacked_seq_no, unacked_segment) in enumerate(self.unacked_segments):
                    if unacked_seq_no > self.last_acked_no - 1:
                        smallest_unacked_segment_idx = i
                        break

                if smallest_unacked_segment_idx is None:
                    self.unacked_segments = []
                else:
                    self.unacked_segments = self.unacked_segments[i:]
                    self.timer = asyncio.get_event_loop().call_later(0.5, self._resend_timer)

            # ACK do fechamento
            if self.prestes_a_fechar:
                self.servidor.remover_conexao(self.id_conexao)
                return

            # Não precisa responder
            if len(payload) == 0:
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
            self.enviar_segmento(
                self.current_seq_no,
                self.expected_seq_no,
                FLAGS_ACK,
                dados[:MSS]
            )
            dados = dados[MSS:]

        self.enviar_segmento(
            self.current_seq_no,
            self.expected_seq_no,
            FLAGS_ACK,
            dados
        )

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
        self.unacked_segments.append((seq_no, segment))
        self.servidor.rede.enviar(segment, self.id_conexao[0])

        if (flags & FLAGS_SYN) == FLAGS_SYN or (flags & FLAGS_FIN) == FLAGS_FIN:
            self.current_seq_no += 1
        else:
            self.current_seq_no += len(payload)

        if self.timer is None:
            self.timer = asyncio.get_event_loop().call_later(0.5, self._resend_timer)

    def _resend_timer(self):
        if len(self.unacked_segments) > 0:
            self.servidor.rede.enviar(self.unacked_segments[0][1], self.id_conexao[0])
        
        self.timer = asyncio.get_event_loop().call_later(0.5, self._resend_timer)

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
