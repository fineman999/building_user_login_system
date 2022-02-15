import pymongo

MONGO_HOST ='localhost'
MONGO_CONN =pymongo.MongoClient('mongodb://%s' %(MONGO_HOST))

def conn_mongodb():
    try:
        MONGO_CONN.admin.command('ismaster')
        site_ab = MONGO_CONN.site_session_db.site_ab
    except:
        MONGO_CONN = pymongo.MongoClient('mongodb://%s'%(MONGO_HOST))
        site_ab = MONGO_CONN.site_session_db.site_ab
    return site_ab