# -*- coding: utf-8 -*-
##############################################################################
# For copyright and license notices, see __openerp__.py file in module root
# directory
##############################################################################

from openerp import fields, models, api, _
from openerp.exceptions import UserError
from datetime import datetime, timedelta
import logging
from lxml import etree
from lxml.etree import Element, SubElement
from lxml import objectify
from lxml.etree import XMLSyntaxError
from openerp import SUPERUSER_ID

import xml.dom.minidom
import pytz


import socket
import collections

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

# ejemplo de suds
import traceback as tb
import suds.metrics as metrics
#from tests import *
#from suds import WebFault
#from suds.client import Client
# from suds.sax.text import Raw
# import suds.client as sudscl

try:
    from suds.client import Client
except:
    pass
# from suds.transport.https import WindowsHttpAuthenticated
# from suds.cache import ObjectCache

# ejemplo de suds

# intento con urllib3
try:
    import urllib3
except:
    pass

# from urllib3 import HTTPConnectionPool
#urllib3.disable_warnings()
pool = urllib3.PoolManager()
# ca_certs = "/etc/ssl/certs/ca-certificates.crt"
# pool = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=ca_certs)
import textwrap

# from inspect import currentframe, getframeinfo
# estas 2 lineas son para imprimir el numero de linea del script
# (solo para debug)

_logger = logging.getLogger(__name__)

try:
    import xmltodict
except ImportError:
    _logger.info('Cannot import xmltodict library')

try:
    import dicttoxml
except ImportError:
    _logger.info('Cannot import dicttoxml library')

try:
    from elaphe import barcode
except ImportError:
    _logger.info('Cannot import elaphe library')

try:
    import M2Crypto
except ImportError:
    _logger.info('Cannot import M2Crypto library')

try:
    import base64
except ImportError:
    _logger.info('Cannot import base64 library')

try:
    import hashlib
except ImportError:
    _logger.info('Cannot import hashlib library')

try:
    import cchardet
except ImportError:
    _logger.info('Cannot import cchardet library')

try:
    from SOAPpy import SOAPProxy
except ImportError:
    _logger.info('Cannot import SOOAPpy')

try:
    from signxml import xmldsig, methods
except ImportError:
    _logger.info('Cannot import signxml')

server_url = {'SIIHOMO':'https://maullin.sii.cl/DTEWS/','SII':'https://palena.sii.cl/DTEWS/'}

BC = '''-----BEGIN CERTIFICATE-----\n'''
EC = '''\n-----END CERTIFICATE-----\n'''

# hardcodeamos este valor por ahora
import os
xsdpath = os.path.dirname(os.path.realpath(__file__)).replace('/models','/static/xsd/')

connection_status = {
    '0': 'Upload OK',
    '1': 'El Sender no tiene permiso para enviar',
    '2': 'Error en tamaño del archivo (muy grande o muy chico)',
    '3': 'Archivo cortado (tamaño <> al parámetro size)',
    '5': 'No está autenticado',
    '6': 'Empresa no autorizada a enviar archivos',
    '7': 'Esquema Invalido',
    '8': 'Firma del Documento',
    '9': 'Sistema Bloqueado',
    'Otro': 'Error Interno.',
}

class Libro(models.Model):
    _name = "account.move.book"

    def split_cert(self, cert):
        certf, j = '', 0
        for i in range(0, 29):
            certf += cert[76 * i:76 * (i + 1)] + '\n'
        return certf

    def create_template_envio(self, RutEmisor, PeriodoTributario, FchResol, NroResol, EnvioDTE,signature_d,TipoOperacion='VENTA',TipoLibro='MENSUAL',TipoEnvio='TOTAL',FolioNotificacion="123", IdEnvio='SetDoc'):
        if TipoLibro in ['ESPECIAL']:
            FolioNotificacion = '<FolioNotificacion>{0}</FolioNotificacion>'.format(FolioNotificacion)
        else:
            FolioNotificacion = ''
        xml = '''<EnvioLibro ID="{10}">
<Caratula>
<RutEmisorLibro>{0}</RutEmisorLibro>
<RutEnvia>{1}</RutEnvia>
<PeriodoTributario>{2}</PeriodoTributario>
<FchResol>{3}</FchResol>
<NroResol>{4}</NroResol>
<TipoOperacion>{5}</TipoOperacion>
<TipoLibro>{6}</TipoLibro>
<TipoEnvio>{7}</TipoEnvio>
{8}
</Caratula>
{9}
</EnvioLibro>
'''.format(RutEmisor, signature_d['subject_serial_number'], PeriodoTributario,
           FchResol, NroResol,TipoOperacion, TipoLibro,TipoEnvio,FolioNotificacion, EnvioDTE,IdEnvio)
        return xml

    def time_stamp(self, formato='%Y-%m-%dT%H:%M:%S'):
        tz = pytz.timezone('America/Santiago')
        return datetime.now(tz).strftime(formato)

    '''
    Funcion auxiliar para conversion de codificacion de strings
     proyecto experimentos_dte
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2014-12-01
    '''
    def convert_encoding(self, data, new_coding = 'UTF-8'):
        encoding = cchardet.detect(data)['encoding']
        if new_coding.upper() != encoding.upper():
            data = data.decode(encoding, data).encode(new_coding)
        return data

    '''
    Funcion para validar los xml generados contra el esquema que le corresponda
    segun el tipo de documento.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def xml_validator(self, some_xml_string, validacion='doc'):
        if 1==1:
            validacion_type = {
                'doc': 'DTE_v10.xsd',
                'env': 'EnvioDTE_v10.xsd',
                'sig': 'xmldsignature_v10.xsd',
                'libro': 'LibroCV_v10.xsd',
                'libroS': 'LibroCVS_v10.xsd',
            }
            xsd_file = xsdpath+validacion_type[validacion]
            try:
                schema = etree.XMLSchema(file=xsd_file)
                parser = objectify.makeparser(schema=schema)
                objectify.fromstring(some_xml_string, parser)
                return True
            except XMLSyntaxError as e:
                raise Warning(_('XML Malformed Error %s') % e.args)

    '''
    Funcion usada en autenticacion en SII
    Obtencion de la semilla desde el SII.
    Basada en función de ejemplo mostrada en el sitio edreams.cl
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-04-01
    '''
    def get_seed(self, company_id):
        #En caso de que haya un problema con la validación de certificado del sii ( por una mala implementación de ellos)
        #esto omite la validacion
        import ssl
        ssl._create_default_https_context = ssl._create_unverified_context
        url = server_url[company_id.dte_service_provider] + 'CrSeed.jws?WSDL'
        ns = 'urn:'+server_url[company_id.dte_service_provider] + 'CrSeed.jws'
        _server = SOAPProxy(url, ns)
        root = etree.fromstring(_server.getSeed())
        semilla = root[0][0].text
        return semilla

    '''
    Funcion usada en autenticacion en SII
    Creacion de plantilla xml para realizar el envio del token
    Previo a realizar su firma
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_seed(self, seed):
        xml = u'''<getToken>
<item>
<Semilla>{}</Semilla>
</item>
</getToken>
'''.format(seed)
        return xml

    '''
    Funcion usada en autenticacion en SII
    Creacion de plantilla xml para envolver el Envio de DTEs
    Previo a realizar su firma (2da)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_env(self, doc,simplificado=False):
        simp = 'http://www.sii.cl/SiiDte LibroCV_v10.xsd'
        if simplificado:
            simp ='http://www.sii.cl/SiiDte LibroCVS_v10.xsd'
        xml = '''<LibroCompraVenta xmlns="http://www.sii.cl/SiiDte" \
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xsi:schemaLocation="{0}" \
version="1.0">
{1}</LibroCompraVenta>'''.format(simp, doc)
        return xml

    '''
    Funcion usada en autenticacion en SII
    Firma de la semilla utilizando biblioteca signxml
    De autoria de Andrei Kislyuk https://github.com/kislyuk/signxml
    (en este caso particular esta probada la efectividad de la libreria)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def sign_seed(self, message, privkey, cert):
        doc = etree.fromstring(message)
        signed_node = xmldsig(
            doc, digest_algorithm=u'sha1').sign(
            method=methods.enveloped, algorithm=u'rsa-sha1',
            key=privkey.encode('ascii'),
            cert=cert)
        msg = etree.tostring(
            signed_node, pretty_print=True).replace('ds:', '')
        return msg

    '''
    Funcion usada en autenticacion en SII
    Obtencion del token a partir del envio de la semilla firmada
    Basada en función de ejemplo mostrada en el sitio edreams.cl
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def get_token(self, seed_file,company_id):
        url = server_url[company_id.dte_service_provider] + 'GetTokenFromSeed.jws?WSDL'
        ns = 'urn:'+ server_url[company_id.dte_service_provider] +'GetTokenFromSeed.jws'
        _server = SOAPProxy(url, ns)
        tree = etree.fromstring(seed_file)
        ss = etree.tostring(tree, pretty_print=True, encoding='iso-8859-1')
        respuesta = etree.fromstring(_server.getToken(ss))
        token = respuesta[0][0].text
        return token

    def ensure_str(self,x, encoding="utf-8", none_ok=False):
        if none_ok is True and x is None:
            return x
        if not isinstance(x, str):
            x = x.decode(encoding)
        return x
    def long_to_bytes(self, n, blocksize=0):
        """long_to_bytes(n:long, blocksize:int) : string
        Convert a long integer to a byte string.
        If optional blocksize is given and greater than zero, pad the front of the
        byte string with binary zeros so that the length is a multiple of
        blocksize.
        """
        # after much testing, this algorithm was deemed to be the fastest
        s = b''
        n = long(n)  # noqa
        import struct
        pack = struct.pack
        while n > 0:
            s = pack(b'>I', n & 0xffffffff) + s
            n = n >> 32
        # strip off leading zeros
        for i in range(len(s)):
            if s[i] != b'\000'[0]:
                break
        else:
            # only happens when n == 0
            s = b'\000'
            i = 0
        s = s[i:]
        # add back some pad bytes.  this could be done more efficiently w.r.t. the
        # de-padding being done above, but sigh...
        if blocksize > 0 and len(s) % blocksize:
            s = (blocksize - len(s) % blocksize) * b'\000' + s
        return s

    def sign_full_xml(self, message, privkey, cert, uri, type='libro'):
        doc = etree.fromstring(message)
        string = etree.tostring(doc[0])
        mess = etree.tostring(etree.fromstring(string), method="c14n")
        digest = base64.b64encode(self.digest(mess))
        reference_uri='#'+uri
        signed_info = Element("SignedInfo")
        c14n_method = SubElement(signed_info, "CanonicalizationMethod", Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315')
        sign_method = SubElement(signed_info, "SignatureMethod", Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1')
        reference = SubElement(signed_info, "Reference", URI=reference_uri)
        transforms = SubElement(reference, "Transforms")
        SubElement(transforms, "Transform", Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
        digest_method = SubElement(reference, "DigestMethod", Algorithm="http://www.w3.org/2000/09/xmldsig#sha1")
        digest_value = SubElement(reference, "DigestValue")
        digest_value.text = digest
        signed_info_c14n = etree.tostring(signed_info,method="c14n",exclusive=False,with_comments=False,inclusive_ns_prefixes=None)
        att = 'xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        #@TODO Find better way to add xmlns:xsi attrib
        signed_info_c14n = signed_info_c14n.replace("<SignedInfo>","<SignedInfo " + att + ">")
        sig_root = Element("Signature",attrib={'xmlns':'http://www.w3.org/2000/09/xmldsig#'})
        sig_root.append(etree.fromstring(signed_info_c14n))
        signature_value = SubElement(sig_root, "SignatureValue")
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        import OpenSSL
        from OpenSSL.crypto import *
        type_ = FILETYPE_PEM
        key=OpenSSL.crypto.load_privatekey(type_,privkey.encode('ascii'))
        signature= OpenSSL.crypto.sign(key,signed_info_c14n,'sha1')
        signature_value.text =textwrap.fill(base64.b64encode(signature),64)
        key_info = SubElement(sig_root, "KeyInfo")
        key_value = SubElement(key_info, "KeyValue")
        rsa_key_value = SubElement(key_value, "RSAKeyValue")
        modulus = SubElement(rsa_key_value, "Modulus")
        key = load_pem_private_key(privkey.encode('ascii'),password=None, backend=default_backend())
        modulus.text =  textwrap.fill(base64.b64encode(self.long_to_bytes(key.public_key().public_numbers().n)),64)
        exponent = SubElement(rsa_key_value, "Exponent")
        exponent.text = self.ensure_str(base64.b64encode(self.long_to_bytes(key.public_key().public_numbers().e)))
        x509_data = SubElement(key_info, "X509Data")
        x509_certificate = SubElement(x509_data, "X509Certificate")
        x509_certificate.text = '\n'+textwrap.fill(cert,64)
        msg = etree.tostring(sig_root)
        msg = msg if self.xml_validator(msg, 'sig') else ''
        fulldoc = message.replace('</LibroCompraVenta>',msg+'\n</LibroCompraVenta>')
        fulldoc = '<?xml version="1.0" encoding="ISO-8859-1"?>\n'+fulldoc
        fulldoc = fulldoc if self.xml_validator(fulldoc, type) else ''
        return fulldoc

    def get_digital_signature_pem(self, comp_id):
        obj = self.env['res.users'].browse([self.env.user.id])
        if not obj.cert:
            obj = self.env['res.company'].browse([comp_id.id])
            if not obj.cert:
                obj = self.env['res.users'].search(domain=[("authorized_users_ids","=", self.env.user.id)])
            if not obj.cert or not self.env.user.id in obj.authorized_users_ids.ids:
                return False
        signature_data = {
            'subject_name': obj.name,
            'subject_serial_number': obj.subject_serial_number,
            'priv_key': obj.priv_key,
            'cert': obj.cert,
            'rut_envia': obj.subject_serial_number
            }
        return signature_data

    def get_digital_signature(self, comp_id):
        obj = self.env['res.users'].browse([self.env.user.id])
        if not obj.cert:
            obj = self.env['res.company'].browse([comp_id.id])
            if not obj.cert:
                obj = self.env['res.users'].search(domain=[("authorized_users_ids","=", self.env.user.id)])
            if not obj.cert or not self.env.user.id in obj.authorized_users_ids.ids:
                return False
        signature_data = {
            'subject_name': obj.name,
            'subject_serial_number': obj.subject_serial_number,
            'priv_key': obj.priv_key,
            'cert': obj.cert}
        return signature_data

    '''
    Funcion usada en SII
    Toma los datos referentes a la resolución SII que autoriza a
    emitir DTE
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def get_resolution_data(self, comp_id):
        resolution_data = {
            'dte_resolution_date': comp_id.dte_resolution_date,
            'dte_resolution_number': comp_id.dte_resolution_number}
        return resolution_data

    @api.multi
    def send_xml_file(self, envio_dte=None, file_name="envio",company_id=False):
        if not company_id.dte_service_provider:
            raise UserError(_("Not Service provider selected!"))
        if 1==1:
            try:
                signature_d = self.get_digital_signature_pem(
                    company_id)
                seed = self.get_seed(company_id)
                template_string = self.create_template_seed(seed)
                seed_firmado = self.sign_seed(
                    template_string, signature_d['priv_key'],
                    signature_d['cert'])
                token = self.get_token(seed_firmado,company_id)
            except:
                raise Warning(connection_status[response.e])
        else:
            return {'sii_result': 'NoEnviado'}
        url = 'https://palena.sii.cl'
        if company_id.dte_service_provider == 'SIIHOMO':
            url = 'https://maullin.sii.cl'
        post = '/cgi_dte/UPL/DTEUpload'
        headers = {
            'Accept': 'image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-powerpoint, application/ms-excel, application/msword, */*',
            'Accept-Language': 'es-cl',
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'Mozilla/4.0 (compatible; PROG 1.0; Windows NT 5.0; YComp 5.0.2.4)',
            'Referer': '{}'.format(company_id.website),
            'Connection': 'Keep-Alive',
            'Cache-Control': 'no-cache',
            'Cookie': 'TOKEN={}'.format(token),
        }
        params = collections.OrderedDict()
        params['rutSender'] = signature_d['subject_serial_number'][:8]
        params['dvSender'] = signature_d['subject_serial_number'][-1]
        params['rutCompany'] = company_id.vat[2:-1]
        params['dvCompany'] = company_id.vat[-1]
        file_name = file_name + '.xml'
        params['archivo'] = (file_name,envio_dte,"text/xml")
        multi  = urllib3.filepost.encode_multipart_formdata(params)
        headers.update({'Content-Length': '{}'.format(len(multi[0]))})
        response = pool.request_encode_body('POST', url+post, params, headers)
        retorno = {'sii_xml_response': response.data, 'sii_result': 'NoEnviado','sii_send_ident':''}
        if response.status != 200:
            return retorno
        respuesta_dict = xmltodict.parse(response.data)
        if respuesta_dict['RECEPCIONDTE']['STATUS'] != '0':
            _logger.info('l736-status no es 0')
            _logger.info(connection_status[respuesta_dict['RECEPCIONDTE']['STATUS']])
        else:
            retorno.update({'sii_result': 'Enviado','sii_send_ident':respuesta_dict['RECEPCIONDTE']['TRACKID']})
        return retorno

    '''
    Funcion para descargar el xml en el sistema local del usuario
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    @api.multi
    def get_xml_file(self):
        file_name = self.name.replace(' ','_')
        return {
            'type' : 'ir.actions.act_url',
            'url': '/web/binary/download_document?model=account.move.book\
&field=sii_xml_request&id=%s&filename=%s.xml' % (self.id, file_name),
            'target': 'self',
        }

    '''
    Funcion para reformateo del vat desde modo Odoo (dos digitos pais sin guion)
    a valor sin puntuacion con guion
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def format_vat(self, value):
        return value[2:10] + '-' + value[10:]

    '''
    Funcion usada en SII
    para firma del timbre (dio errores de firma para el resto de los doc)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-03-01
    '''
    def digest(self, data):
        sha1 = hashlib.new('sha1', data)
        return sha1.digest()

    @api.onchange('periodo_tributario','tipo_operacion')
    def _setName(self):
        if self.name:
            return
        self.name = self.tipo_operacion
        if self.periodo_tributario:
            self.name += " " + self.periodo_tributario

    sii_message = fields.Text(
        string='SII Message',
        copy=False)
    sii_xml_request = fields.Text(
        string='SII XML Request',
        copy=False)
    sii_xml_response = fields.Text(
        string='SII XML Response',
        copy=False)
    sii_send_ident = fields.Text(
        string='SII Send Identification',
        copy=False)
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('NoEnviado', 'No Enviado'),
        ('Enviado', 'Enviado'),
        ('Aceptado', 'Aceptado'),
        ('Rechazado', 'Rechazado'),
        ('Reparo', 'Reparo'),
        ('Proceso', 'Proceso'),
        ('Reenviar', 'Reenviar'),
        ('Anulado', 'Anulado')],
        'Resultado'
        , index=True, readonly=True, default='draft',
        track_visibility='onchange', copy=False,
        help=" * The 'Draft' status is used when a user is encoding a new and unconfirmed Invoice.\n"
             " * The 'Pro-forma' status is used the invoice does not have an invoice number.\n"
             " * The 'Open' status is used when user create invoice, an invoice number is generated. Its in open status till user does not pay invoice.\n"
             " * The 'Paid' status is set automatically when the invoice is paid. Its related journal entries may or may not be reconciled.\n"
             " * The 'Cancelled' status is used when user cancel invoice.")
    move_ids = fields.Many2many('account.move')

    tipo_libro = fields.Selection([('ESPECIAL','Especial'),('MENSUAL','Mensual')], string="Tipo de Libro",default='MENSUAL', required=True)
    tipo_operacion = fields.Selection([('COMPRA','Compras'),('VENTA','Ventas')], string="Tipo de operación",default="COMPRA", required=True)
    tipo_envio = fields.Selection([('AJUSTE','Ajuste'),('TOTAL','Total'),('PARCIAL','Parcial'),('TOTAL','Total')], string="Tipo de Envío", default="TOTAL", required=True)
    folio_notificacion = fields.Char(string="Folio de Notificación")
    #total_afecto = fields.Char(string="Total Afecto")
    #total_exento = fields.Char(string="Total Exento")
    periodo_tributario = fields.Char('Periodo Tributario', required=True)
    company_id = fields.Many2one('res.company', required=True)
    name = fields.Char(string="Detalle" , required=True)
    fact_prop = fields.Float(string="Factor proporcionalidad")

    @api.multi
    def validar_libro(self):
        return self.write({'state': 'NoEnviado'})

    def _acortar_str(self, texto, size=1):
        c = 0
        cadena = ""
        while c < size and c < len(texto):
            cadena += texto[c]
            c += 1
        return cadena

    def getResumen(self, rec):
        if rec.document_class_id.sii_code in [56,64] or self.tipo_operacion in ['COMPRA']:
            ob = self.env['account.invoice']
            ref = ob.search([('number','=',rec.document_number)])
            referencia = self.env['account.move'].search([('document_number','=',ref.origin)])
        else:
            referencia = self.env['account.invoice'].search([('number','=',rec.document_number)])
        det = collections.OrderedDict()
        det['TpoDoc'] = rec.document_class_id.sii_code
        #det['Emisor']
        #if rec.document_class_id.sii_code in['55','56','60','61'] :@TODO buscar documento de referencia
            #det['IndFactCompra']#si la nota de credito o debito afecta a factura de compra
        if self.tipo_operacion in ['COMPRA']:
            det['NroDoc'] = int(rec.ref)
        else:
            det['NroDoc'] = int(rec.sii_document_number)
        #if rec.is_anulation:
        #    det['Anulado'] = 'A'
        #det['Operacion']
        imp = {}
        Neto = 0
        MntExe = 0
        TaxMnt = 0
        tasa = False
        for l in rec.line_ids:
            if l.tax_line_id:
                if l.tax_line_id and l.tax_line_id.amount > 0: #supuesto iva único
                    tasa = l.tax_line_id
                    if l.credit > 0:
                        TaxMnt += l.credit
                    else:
                        TaxMnt += l.debit
            elif l.tax_ids and l.tax_ids.amount > 0:
                if l.credit > 0:
                    Neto += l.credit
                else:
                    Neto += l.debit
            elif l.tax_ids and l.tax_ids.amount == 0: #caso monto exento
                if l.credit > 0:
                    MntExe += l.credit
                else:
                    MntExe += l.debit
        if tasa :
            if tasa.sii_code in [14]:
                det['TpoImp'] = 1
            #elif tasa.sii_code in []: determinar cuando es 18.211 // zona franca
            #    det['TpoImp'] = 2
            det['TasaImp'] = round(tasa.amount,2)
        #det['IndServicio']
        #det['IndSinCosto']
        det['FchDoc'] = rec.date
        if 1==2:#@TODO Sucursales
            det['CdgSIISucur']=False
        det['RUTDoc'] = self.format_vat(rec.partner_id.vat)
        det['RznSoc'] = rec.partner_id.name[:50]
        if referencia:
            if self.tipo_operacion in ['COMPRA']:
                det['TpoDocRef'] = referencia.document_class_id.sii_code
                det['FolioDocRef'] = referencia.ref
            else:
                det['TpoDocRef'] = referencia.journal_document_class_id.sii_code
                det['FolioDocRef'] = referencia.origin
        if MntExe > 0 :
            det['MntExe'] = int(round(MntExe,0))
        elif self.tipo_operacion in ['VENTA'] and not Neto > 0:
            det['MntExe'] = 0
        if Neto > 0:
            det['MntNeto'] = int(round(Neto))
            if tasa.sii_code in [14] or tasa.sii_type: # Es algún tipo de iva que puede ser adicional anticipado
                if rec.no_rec_code or rec.iva_uso_comun:
                    det['MntIVA'] = 0
                else:
                    det['MntIVA'] = int(round(TaxMnt))
                if rec.no_rec_code:
                    det['IVANoRec'] = collections.OrderedDict()
                    det['IVANoRec']['CodIVANoRec'] = rec.no_rec_code
                    det['IVANoRec']['MntIVANoRec'] = int(round(TaxMnt))
                if rec.iva_uso_comun:
                    det['IVAUsoComun'] = int(round(TaxMnt))
            if tasa.sii_code not in [0,14]:#niva
                det['OtrosImp'] = collections.OrderedDict()
                det['OtrosImp']['CodImp'] = tasa.sii_code
                det['OtrosImp']['TasaImp'] = tasa.amount
                det['OtrosImp']['MntImp'] = int(round(TaxMnt))
            if tasa and tasa.sii_type in ['R']:
                if tasa.retencion == tasa.amount:
                    det['IVARetTotal'] = int(round(TaxMnt))
                else:
                    det['IVARetParcial'] = int(round(Neto * (tasa.retencion / 100)))
                    det['IVANoRetenido'] = int(round(TaxMnt - (Neto * (tasa.retencion / 100))))
                TaxMnt = 0
        monto_total = int(round((Neto + MntExe + TaxMnt), 0))
        det['MntTotal'] = monto_total
        return det

    def _setResumenPeriodo(self,resumen,resumenP):
        resumenP['TpoDoc'] = resumen['TpoDoc']
        if 'TpoImp' in resumen:
            resumenP['TpoImp'] = resumen['TpoImp'] or 1
        if not 'TotDoc' in resumenP:
            resumenP['TotDoc'] = 1
        else:
            resumenP['TotDoc'] += 1
        if 'TotAnulado' in resumen:
            resumenP['TotAnulado'] += 1
        elif 'Anulado' in resumen:
            resumenP['TotAnulado'] = 1
        if 'MntExe' in resumen and not 'TotMntExe' in resumenP:
            resumenP['TotMntExe'] = resumen['MntExe']
        elif 'MntExe' in resumen:
            resumenP['TotMntExe'] += resumen['MntExe']
        elif not 'TotMntExe' in resumenP:
            resumenP['TotMntExe'] = 0
        if 'MntNeto' in resumen and not 'TotMntNeto' in resumenP:
            resumenP['TotMntNeto'] = resumen['MntNeto']
        elif 'MntNeto' in resumen:
            resumenP['TotMntNeto'] += resumen['MntNeto']
        elif not 'TotMntNeto' in resumenP:
            resumenP['TotMntNeto'] = 0
        if 'TotOpIVARec' in resumen:
            resumenP['TotOpIVARec'] = resumen['OpIVARec']
        if 'MntIVA' in resumen and not 'TotMntIVA' in resumenP:
            resumenP['TotMntIVA'] = resumen['MntIVA']
        elif 'MntIVA' in resumen:
            resumenP['TotMntIVA'] += resumen['MntIVA']
        elif not 'TotMntIVA' in resumenP:
            resumenP['TotMntIVA'] = 0
        #resumenP['TotOpActivoFijo'] = resumen['TotOpActivoFijo']
        #resumenP['TotMntIVAActivoFijo'] = resumen['TotMntIVAActivoFijo']
        if 'IVANoRec' in resumen and not 'itemNoRec' in resumenP:
            tot = {}
            tot['TotIVANoRec'] = collections.OrderedDict()
            tot['TotIVANoRec']['CodIVANoRec'] = resumen['IVANoRec']['CodIVANoRec']
            tot['TotIVANoRec']['TotOpIVANoRec'] = 1
            tot['TotIVANoRec']['TotMntIVANoRec'] = resumen['IVANoRec']['MntIVANoRec']
            resumenP['itemNoRec'] = [tot]
        elif 'IVANoRec' in resumen:
            seted = False
            itemNoRec = []
            for r in resumenP['itemNoRec']:
                if r['TotIVANoRec']['CodIVANoRec'] == resumen['IVANoRec']['CodIVANoRec']:
                    r['TotIVANoRec']['TotOpIVANoRec'] += 1
                    r['TotIVANoRec']['TotMntIVANoRec'] += resumen['IVANoRec']['MntIVANoRec']
                    seted = True
                itemNoRec.extend([r])
            if not seted:
                tot = {}
                tot['TotIVANoRec'] = collections.OrderedDict()
                tot['TotIVANoRec']['CodIVANoRec'] = resumen['IVANoRec']['CodIVANoRec']
                tot['TotIVANoRec']['TotOpIVANoRec'] = 1
                tot['TotIVANoRec']['TotMntIVANoRec'] = resumen['IVANoRec']['MntIVANoRec']
                itemNoRec.extend([tot])
            resumenP['itemNoRec'] = itemNoRec

        if 'IVAUsoComun' in resumen and not 'TotOpIVAUsoComun' in resumenP:
            resumenP['TotOpIVAUsoComun'] = 1
            resumenP['TotIVAUsoComun'] = resumen['IVAUsoComun']
            resumenP['FctProp'] = self.fact_prop
            resumenP['TotCredIVAUsoComun'] = int(round((resumen['IVAUsoComun'] * self.fact_prop )))
        elif 'IVAUsoComun' in resumen:
            resumenP['TotOpIVAUsoComun'] += 1
            resumenP['TotIVAUsoComun'] += resumen['IVAUsoComun']
            resumenP['TotCredIVAUsoComun'] += int(round((resumen['IVAUsoComun'] * self.fact_prop )))
        if not 'itemOtrosImp' in resumenP and 'OtrosImp' in resumen :
            tot = {}
            tot['TotOtrosImp'] = collections.OrderedDict()
            tot['TotOtrosImp']['CodImp']  = resumen['OtrosImp']['CodImp']
            tot['TotOtrosImp']['TotMntImp']  = resumen['OtrosImp']['MntImp']
            #tot['FctImpAdic']
            #tot['TotOtrosImp']['TotCredImp']  = TaxMnt
            resumenP['itemOtrosImp'] = [tot]
        elif 'OtrosImp' in resumen:
            seted = False
            itemOtrosImp = []
            for r in resumenP['itemOtrosImp']:
                if r['TotOtrosImp']['CodImp'] == resumen['OtrosImp']['CodImp']:
                    r['TotOtrosImp']['TotMntImp'] += resumen['OtrosImp']['MntImp']
                    seted = True
                itemOtrosImp.extend([r])
            if not seted:
                tot = {}
                tot['TotOtrosImp'] = collections.OrderedDict()
                tot['TotOtrosImp']['CodImp']  = resumen['OtrosImp']['CodImp']
                tot['TotOtrosImp']['TotMntImp']  = resumen['MntImp']
                #tot['FctImpAdic']
                #tot['TotOtrosImp']['TotCredImp']  = TaxMnt
                itemOtrosImp.extend([tot])
            resumenP['itemOtrosImp'] = itemOtrosImp
        if 'IVARetTotal' in resumen and not 'TotIVARetTotal' in resumenP:
            resumenP['TotIVARetTotal'] = resumen['IVARetTotal']
        elif 'IVARetTotal' in resumen:
            resumenP['TotIVARetTotal'] += resumen['IVARetTotal']
        if 'IVARetParcial' in resumen and not 'TotIVARetParcial' in resumenP:
            resumenP['TotIVARetParcial'] = resumen['IVARetParcial']
            resumenP['TotIVANoRetenido'] = resumen['IVANoRetenido']
        elif 'IVARetParcial' in resumen:
            resumenP['TotIVARetParcial'] += resumen['IVARetParcial']
            resumenP['TotIVANoRetenido'] += resumen['IVANoRetenido']

        #@TODO otros tipos IVA
        if not 'TotMntTotal' in resumenP:
            resumenP['TotMntTotal'] = resumen['MntTotal']
        else:
            resumenP['TotMntTotal'] += resumen['MntTotal']
        return resumenP

    @api.multi
    def do_dte_send_book(self):
        dicttoxml.set_debug(False)
        cant_doc_batch = 0
        company_id = self.company_id
        dte_service = company_id.dte_service_provider
        try:
            signature_d = self.get_digital_signature(company_id)
        except:
            raise Warning(_('''There is no Signer Person with an \
        authorized signature for you in the system. Please make sure that \
        'user_signature_key' module has been installed and enable a digital \
        signature, for you or make the signer to authorize you to use his \
        signature.'''))
        certp = signature_d['cert'].replace(
            BC, '').replace(EC, '').replace('\n', '')
        resumenes = []
        resumenesPeriodo = {}
        for rec in self.with_context(lang='es_CL').move_ids:
            rec.sended = True
            resumen = self.getResumen(rec)
            resumenes.extend([{'Detalle':resumen}])
            TpoDoc= resumen['TpoDoc']
            if not TpoDoc in resumenesPeriodo:
                resumenesPeriodo[TpoDoc] = {}
            resumenesPeriodo[TpoDoc] = self._setResumenPeriodo(resumen, resumenesPeriodo[TpoDoc])
        lista = ['TpoDoc', 'TpoImp', 'TotDoc', 'TotAnulado', 'TotMntExe', 'TotMntNeto', 'TotOpIVARec',
                'TotMntIVA', 'TotMntIVA', 'TotOpActivoFijo', 'TotMntIVAActivoFijo', 'itemNoRec', 'TotOpIVAUsoComun',
                'TotIVAUsoComun', 'FctProp', 'TotCredIVAUsoComun', 'itemOtrosImp', 'TotImpSinCredito', 'TotIVARetTotal',
                  'TotIVARetParcial', 'TotMntTotal', 'TotIVANoRetenido',
                 'TotTabPuros', 'TotTabCigarrillos', 'TotTabElaborado', 'TotImpVehiculo',]
        ResumenPeriodo=[]
        for r, value in resumenesPeriodo.iteritems():
            total = collections.OrderedDict()
            for v in lista:
                if v in value:
                    total[v] = value[v]
            ResumenPeriodo.extend([{'TotalesPeriodo':total}])
        dte = collections.OrderedDict()
        dte['ResumenPeriodo'] = collections.OrderedDict()
        dte['ResumenPeriodo'] = ResumenPeriodo
        dte['item'] = resumenes
        dte['TmstFirma'] = self.time_stamp()

        resol_data = self.get_resolution_data(company_id)
        RUTEmisor = self.format_vat(company_id.vat)
        RUTRecep = "60803000-K" # RUT SII
        xml = dicttoxml.dicttoxml(
            dte, root=False, attr_type=False)
        doc_id =  self.tipo_operacion+'_'+self.periodo_tributario
        libro = self.create_template_envio( RUTEmisor, self.periodo_tributario,
            resol_data['dte_resolution_date'],
            resol_data['dte_resolution_number'],
            xml, signature_d,self.tipo_operacion,self.tipo_libro,self.tipo_envio,self.folio_notificacion, doc_id)
        xml  = self.create_template_env(libro)
        root = etree.XML( xml )
        xml_pret = etree.tostring(root, pretty_print=True).replace('<item>','\n').replace('</item>','').replace('<itemNoRec>','').replace('</itemNoRec>','\n').replace('<itemOtrosImp>','').replace('</itemOtrosImp>','\n')
        envio_dte = self.convert_encoding(xml_pret, 'ISO-8859-1')
        envio_dte = self.sign_full_xml(
            envio_dte, signature_d['priv_key'], certp,
            doc_id, 'libro')
        result = self.send_xml_file(envio_dte, doc_id+'.xml', company_id)
        self.write({'sii_xml_response':result['sii_xml_response'], 'sii_send_ident':result['sii_send_ident'], 'state': result['sii_result'],'sii_xml_request':envio_dte})

    def _get_send_status(self, track_id, signature_d,token):
        url = server_url[self.company_id.dte_service_provider] + 'QueryEstUp.jws?WSDL'
        ns = 'urn:'+ server_url[self.company_id.dte_service_provider] + 'QueryEstUp.jws'
        _server = SOAPProxy(url, ns)
        respuesta = _server.getEstUp(self.company_id.vat[2:-1],self.company_id.vat[-1],track_id,token)
        self.sii_message = respuesta
        resp = xmltodict.parse(respuesta)
        status = False
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "-11":
            status =  {'warning':{'title':_('Error -11'), 'message': _("Error -11: Espere a que sea aceptado por el SII, intente en 5s más")}}
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "EPR":
            self.state = "Proceso"
            if resp['SII:RESPUESTA']['SII:RESP_BODY']['RECHAZADOS'] == "1":
                self.sii_result = "Rechazado"
        elif resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "RCT":
            self.state = "Rechazado"
            status = {'warning':{'title':_('Error RCT'), 'message': _(resp['SII:RESPUESTA']['GLOSA'])}}
        return status

    def _get_dte_status(self, signature_d, token):
        url = server_url[self.company_id.dte_service_provider] + 'QueryEstDte.jws?WSDL'
        ns = 'urn:'+ server_url[self.company_id.dte_service_provider] + 'QueryEstDte.jws'
        _server = SOAPProxy(url, ns)
        receptor = self.format_vat(self.partner_id.vat)
        date_invoice = datetime.strptime(self.date_invoice, "%Y-%m-%d").strftime("%d-%m-%Y")
        respuesta = _server.getEstDte(signature_d['subject_serial_number'][:8], str(signature_d['subject_serial_number'][-1]),
                self.company_id.vat[2:-1],self.company_id.vat[-1], receptor[:8],receptor[2:-1],str(self.document_class_id.sii_code), str(self.sii_document_number),
                date_invoice, str(self.amount_total),token)
        self.sii_message = respuesta
        resp = xmltodict.parse(respuesta)
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == '2':
            status = {'warning':{'title':_("Error code: 2"), 'message': _(resp['SII:RESPUESTA']['SII:RESP_HDR']['GLOSA'])}}
            return status
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "EPR":
            self.state = "Proceso"
            if resp['SII:RESPUESTA']['SII:RESP_BODY']['RECHAZADOS'] == "1":
                self.state = "Rechazado"
            if resp['SII:RESPUESTA']['SII:RESP_BODY']['REPARO'] == "1":
                self.state = "Reparo"
        elif resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "RCT":
            self.state = "Rechazado"

    @api.multi
    def ask_for_dte_status(self):
        try:
            signature_d = self.get_digital_signature_pem(
                self.company_id)
            seed = self.get_seed(self.company_id)
            template_string = self.create_template_seed(seed)
            seed_firmado = self.sign_seed(
                template_string, signature_d['priv_key'],
                signature_d['cert'])
            token = self.get_token(seed_firmado,self.company_id)
        except:
            raise Warning(connection_status[response.e])
        xml_response = xmltodict.parse(self.sii_xml_response)
        if self.state == 'Enviado':
            status = self._get_send_status(self.sii_send_ident, signature_d, token)
            if self.state != 'Proceso':
                return status
        return self._get_dte_status(signature_d, token)
