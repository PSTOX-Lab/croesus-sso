/**
 * Created by benoitde on 2023-09-29.
 */

public with sharing class CroesusSSOController {
    public CroesusSSOController() {}

    public PageReference urlRedirection() {
        String state = EncodingUtil.urlDecode(ApexPages.currentPage().getParameters().get('state'), 'utf-8');
        String redirectUrl = EncodingUtil.urlDecode(ApexPages.currentPage().getParameters().get('callback'), 'utf-8');
        String code = EncodingUtil.urlEncode(EncodingUtil.base64Encode(Crypto.generateAesKey(128)), 'utf-8');
        PageReference page = new PageReference(redirectUrl + '?state=' + state +'&code=' + code);
        page.setRedirect(true);
        System.debug(state);
        System.debug(redirectUrl);
        System.debug(code);
        System.debug(page);
        return page;
    }
}