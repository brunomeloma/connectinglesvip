// Preenche os contratos 2027 (arquivos Word em /contratos) com os dados do
// aluno. Trabalha direto no word/document.xml do .docx original: acha cada
// linha do formulário pelo rótulo ("NOME COMPLETO:", "CPF:" ...) e escreve o
// valor logo depois, marca os "( )" e preenche os "____". Assim, para trocar
// o contrato no ano que vem basta substituir o .docx na pasta, sem mexer no
// código, desde que os rótulos continuem os mesmos.
//
// Roda no navegador (window.ContratoDocx) e no Node (module.exports), para
// poder ser testado fora do site.
(function(root){
  'use strict';

  const MODELOS={
    infantil:{arquivo:'contratos/Contrato_Infantil_2027.docx',label:'Infantil (Kids)'},
    regular:{arquivo:'contratos/Contrato_Regular_2027.docx',label:'Regular (turmas)'},
    vip:{arquivo:'contratos/Contrato_VIP_2027.docx',label:'VIP'},
    vip_premium:{arquivo:'contratos/Contrato_VIP_Premium_2027.docx',label:'VIP Premium'},
  };

  // ---------- números por extenso ----------
  const UN=['zero','um','dois','três','quatro','cinco','seis','sete','oito','nove','dez','onze','doze','treze','quatorze','quinze','dezesseis','dezessete','dezoito','dezenove'];
  const DEZ=['','','vinte','trinta','quarenta','cinquenta','sessenta','setenta','oitenta','noventa'];
  const CEN=['','cento','duzentos','trezentos','quatrocentos','quinhentos','seiscentos','setecentos','oitocentos','novecentos'];
  function ate999(n){
    if(n===0) return '';
    if(n===100) return 'cem';
    const c=Math.floor(n/100),r=n%100,p=[];
    if(c) p.push(CEN[c]);
    if(r){
      if(r<20) p.push(UN[r]);
      else{const d=Math.floor(r/10),u=r%10;p.push(u?DEZ[d]+' e '+UN[u]:DEZ[d]);}
    }
    return p.join(' e ');
  }
  function inteiroPorExtenso(n){
    n=Math.floor(Math.abs(Number(n)||0));
    if(n===0) return 'zero';
    const mi=Math.floor(n/1e6),mil=Math.floor((n%1e6)/1000),r=n%1000,p=[];
    if(mi) p.push(mi===1?'um milhão':ate999(mi)+' milhões');
    if(mil) p.push(mil===1?'mil':ate999(mil)+' mil');
    if(r) p.push(ate999(r));
    // "mil e cem", "dois mil e trinta"; "mil cento e dez" fica sem o "e"
    if(p.length>1&&r&&(r<100||r%100===0)) return p.slice(0,-1).join(' ')+' e '+p[p.length-1];
    return p.join(' ');
  }
  function reaisPorExtenso(v){
    v=Math.round((Number(v)||0)*100);
    const reais=Math.floor(v/100),cent=v%100,p=[];
    if(reais){const t=inteiroPorExtenso(reais);p.push(t+((reais%1e6===0)?' de':'')+(reais===1?' real':' reais'));}
    if(cent) p.push(inteiroPorExtenso(cent)+(cent===1?' centavo':' centavos'));
    return p.length?p.join(' e '):'zero reais';
  }

  // ---------- utilidades de XML ----------
  const escXml=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const unXml=s=>s.replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&amp;/g,'&');
  const RE_T=/(<w:t(?:\s[^>]*)?>)([^<]*)(<\/w:t>)/g;
  const RE_RUN=/<w:r(?:\s[^>]*)?>[\s\S]*?<\/w:r>/g;

  function textoParagrafo(p){
    let t='';
    p.replace(RE_T,(m,a,b)=>{t+=unXml(b);return m;});
    return t;
  }
  const norm=s=>s.replace(/\s+/g,' ').trim().toUpperCase();
  const tagPreserve=open=>/xml:space=/.test(open)?open:open.replace('<w:t','<w:t xml:space="preserve"');

  // Procura `re` no texto corrido da linha (o Word costuma picotar "( )" e
  // "____" em vários <w:t>) e troca cada ocorrência por repl(trecho, n);
  // repl devolvendo null mantém o trecho. A troca vai para o primeiro
  // pedaço e o resto do trecho é apagado dos pedaços seguintes.
  function substituir(p,re,repl){
    const nos=[];
    let m;
    RE_T.lastIndex=0;
    while((m=RE_T.exec(p))) nos.push({ini:m.index,fim:m.index+m[0].length,open:m[1],txt:unXml(m[2]),close:m[3]});
    if(!nos.length) return p;
    const pos=[];let acc=0;
    for(const n of nos){pos.push(acc);acc+=n.txt.length;}
    const corrido=nos.map(n=>n.txt).join('');
    const achados=[];let k=0;
    corrido.replace(re,(trecho,...rest)=>{const off=rest[rest.length-2];const r=repl(trecho,k++,off,corrido);if(r!=null) achados.push({s:off,e:off+trecho.length,r});return trecho;});
    if(!achados.length) return p;
    const novos=nos.map(n=>n.txt);
    // de trás para frente: as posições dos achados anteriores continuam valendo
    for(const a of achados.reverse()){
      for(let i=0;i<nos.length;i++){
        const ns=pos[i],ne=pos[i]+nos[i].txt.length;
        if(ne<=a.s||ns>=a.e) continue;
        const ls=Math.max(a.s,ns)-ns,le=Math.min(a.e,ne)-ns;
        novos[i]=novos[i].slice(0,ls)+(ns<=a.s?a.r:'')+novos[i].slice(le);
      }
    }
    let saida=p;
    for(let i=nos.length-1;i>=0;i--){
      if(novos[i]===nos[i].txt) continue;
      saida=saida.slice(0,nos[i].ini)+tagPreserve(nos[i].open)+escXml(novos[i])+nos[i].close+saida.slice(nos[i].fim);
    }
    return saida;
  }

  // Escreve o valor depois do rótulo, num run novo com a mesma formatação
  // do último trecho de texto da linha.
  function acrescentar(p,valor){
    if(valor==null||String(valor).trim()==='') return p;
    let rPr='';
    const runs=p.match(RE_RUN)||[];
    for(let i=runs.length-1;i>=0;i--){
      if(/<w:t[\s>]/.test(runs[i])){const m=runs[i].match(/<w:rPr>[\s\S]*?<\/w:rPr>/);rPr=m?m[0]:'';break;}
    }
    const espaco=/\s$/.test(textoParagrafo(p))?'':' ';
    return p+`<w:r>${rPr}<w:t xml:space="preserve">${escXml(espaco+String(valor).trim())}</w:t></w:r>`;
  }

  // Marca os "( )" da linha, na ordem: flags[i] true → "(X)".
  function marcar(p,flags){
    return substituir(p,/\(\s*\)/g,(m,i)=>flags[i]===undefined?null:(flags[i]?'(X)':'(  )'));
  }

  // Preenche os "____" da linha na ordem; valor vazio mantém o traço.
  function preencherTracos(p,valores,re){
    return substituir(p,re||/_{2,}/g,(m,i,off,corrido)=>{
      const v=valores[i];
      if(v==null||String(v).trim()==='') return null;
      // o traço do original às vezes encosta na palavra seguinte ("____pelos")
      const depois=corrido.charAt(off+m.length);
      return String(v).trim()+(depois&&/[\wÀ-ÿ]/.test(depois)?' ':'');
    });
  }

  // ---------- preenchimento ----------
  function preencherDocumentXml(xml,d){
    const c=d.contratante||{},a=d.aluno||{},pg=d.pagamento||{},v=d.valores||{},vip=d.vip||{},pr=d.premium||{};
    const partes=xml.split('</w:p>');
    let secao=null,periodoVip=1;
    for(let i=0;i<partes.length-1;i++){
      let p=partes[i];
      const ini=p.lastIndexOf('<w:p ')>p.lastIndexOf('<w:p>')?p.lastIndexOf('<w:p '):p.lastIndexOf('<w:p>');
      if(ini<0) continue;
      const N=norm(textoParagrafo(p.slice(ini)));
      if(!N) continue;
      const comeca=s=>N.startsWith(s);
      // "denominada00" do original (o "00" vem num pedaço separado)
      if(N.includes('DENOMINADA00')) p=substituir(p,/denominada00/gi,t=>t.slice(0,-2));

      if(N.includes('QUALIFICAÇÃO DO CONTRATANTE')){secao='c';continue;}
      if(N.includes('QUALIFICAÇÃO DO(A) ALUNO')){secao='a';continue;}
      if(N.includes('PESSOAS AUTORIZADAS')){secao='p';continue;}
      if(N.includes('DA FUNDAMENTAÇÃO LEGAL')){secao=null;continue;}

      if(N.includes('IMPORTÂNCIA DE R$')&&N.includes('__')){
        p=preencherTracos(p,[v.total,v.total_extenso,v.parcelas,v.meses,v.parcela,v.dia,v.dia_extenso]);
      } else if(comeca('IMPERATRIZ, MARANHÃO')&&N.includes('_')){
        p=preencherTracos(p,[d.data_contrato],/_+\s*\/\s*_+\s*\/\s*(?:20\d*)?_*/g);
      } else if(secao==='c'){
        if(comeca('NOME COMPLETO:')) p=acrescentar(p,c.nome);
        else if(comeca('ESTADO CIVIL:')) p=acrescentar(p,c.estado_civil);
        else if(/^\(\s*\) CASADO/.test(N)) p=marcar(p,[c.ec_casado,c.ec_solteiro,c.ec_separado]);
        else if(/^\(\s*\) PAI/.test(N)) p=marcar(p,[c.guarda==='pai',c.guarda==='mae',c.guarda==='avos',c.guarda==='outros']);
        else if(comeca('PROFISSÃO:')) p=acrescentar(p,c.profissao);
        else if(comeca('DATA DE NASCIMENTO:')) p=acrescentar(p,c.nascimento);
        else if(comeca('R.G:')) p=acrescentar(p,c.rg);
        else if(comeca('CPF:')) p=acrescentar(p,c.cpf);
        else if(comeca('GRAU DE PARENTESCO')) p=acrescentar(p,c.parentesco);
        else if(comeca('ENDEREÇO RESIDENCIAL:')) p=acrescentar(p,c.endereco);
        else if(comeca('BAIRRO:')) p=acrescentar(p,c.bairro);
        else if(comeca('CEP:')) p=acrescentar(p,c.cep);
        else if(comeca('CELULAR:')) p=acrescentar(p,c.celular);
        else if(comeca('E-MAIL:')) p=acrescentar(p,c.email);
        else if(comeca('FORMA DE PAGAMENTO:')){
          p=marcar(p,[pg.forma==='vista',pg.forma==='parcelado']);
          if(pg.forma==='parcelado') p=acrescentar(p,pg.parcelas);
        }
        else if(comeca('CORRESPONDENTE NOVEMBRO')) periodoVip=1;
        else if(comeca('CORRESPONDENTE JULHO')) periodoVip=2;
        else if(comeca('DATA DE INGRESSO DO ALUNO')) p=preencherTracos(p,[d.modelo==='vip_premium'?pr.ingresso:(vip.p1||{}).data],/_+\s*\/\s*_+\s*\/\s*_+/g);
        else if(comeca('DATA DE RETORNO DAS AULAS')) p=preencherTracos(p,[(vip.p2||{}).data],/_+\s*\/\s*_+\s*\/\s*_+/g);
        else if(comeca('DATA DE TERMINO')||comeca('DATA DE TÉRMINO')) p=preencherTracos(p,[pr.termino],/_+\s*\/\s*_+\s*\/\s*_+/g);
        else if(N.includes('QUANTIDADE DE ENCONTROS')) p=preencherTracos(p,[d.modelo==='vip_premium'?pr.encontros:(vip['p'+periodoVip]||{}).encontros]);
        else if(N.includes('CARGA HORÁRIA TOTAL')) p=preencherTracos(p,[d.modelo==='vip_premium'?pr.horas:(vip['p'+periodoVip]||{}).horas]);
      } else if(secao==='a'){
        if(comeca('NOME COMPLETO DA MÃE')) p=acrescentar(p,a.mae);
        else if(comeca('NOME COMPLETO DO PAI')) p=acrescentar(p,a.pai);
        else if(comeca('NOME:')) p=acrescentar(p,a.nome);
        else if(comeca('DATA DE NASCIMENTO:')) p=acrescentar(p,a.nascimento);
        else if(comeca('NACIONALIDADE:')) p=acrescentar(p,a.nacionalidade);
        else if(comeca('NATURALIDADE')) p=acrescentar(p,a.naturalidade);
        else if(comeca('CERTIDÃO DE NASCIMENTO')) p=acrescentar(p,a.documento);
        else if(comeca('SEXO:')) p=marcar(p,[a.sexo==='f',a.sexo==='m']);
        else if(comeca('MÓDULO:')) p=marcar(p,[a.modulo==='infantil',a.modulo==='regular']);
        else if(comeca('TURMA:')) p=acrescentar(p,a.turma);
        else if(comeca('NECESSIDADES EDUCACIONAIS')) p=acrescentar(p,a.necessidades);
        else if(comeca('ESCOLA REGULAR')) p=acrescentar(p,a.escola);
      }
      partes[i]=p;
    }
    return partes.join('</w:p>');
  }

  // Erros conhecidos nos arquivos originais, corrigidos em todo documento gerado.
  function corrigirTexto(xml){
    return xml.replace(/40\.477\.269\/001-88/g,'40.477.269/0001-88').replace(/denominada00/g,'denominada');
  }

  // Recebe o .docx original (ArrayBuffer/Uint8Array) e devolve o preenchido.
  // tipoSaida: 'blob' no navegador, 'nodebuffer' no Node.
  async function preencher(JSZip,arquivo,dados,tipoSaida){
    const zip=await JSZip.loadAsync(arquivo);
    const nomes=Object.keys(zip.files).filter(n=>/^word\/(document|header\d*|footer\d*)\.xml$/.test(n));
    if(!nomes.includes('word/document.xml')) throw new Error('Arquivo de contrato inválido (sem word/document.xml).');
    for(const n of nomes){
      let xml=corrigirTexto(await zip.file(n).async('string'));
      if(n==='word/document.xml') xml=preencherDocumentXml(xml,dados);
      zip.file(n,xml);
    }
    return zip.generateAsync({type:tipoSaida||'blob',compression:'DEFLATE',
      mimeType:'application/vnd.openxmlformats-officedocument.wordprocessingml.document'});
  }

  const api={MODELOS,preencher,preencherDocumentXml,textoParagrafo,inteiroPorExtenso,reaisPorExtenso};
  if(typeof module!=='undefined'&&module.exports) module.exports=api;
  else root.ContratoDocx=api;
})(typeof window!=='undefined'?window:this);
